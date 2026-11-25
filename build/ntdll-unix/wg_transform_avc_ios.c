/* H.264 and AAC decoder transforms (wg_transform) on VideoToolbox / AudioToolbox.
 *                                                        (MADEIRA avc-transform)
 *
 * WHY: Black Ops III creates the Media Foundation H.264 decoder MFT at start-up
 * (CLSID_MSH264DecoderMFT, msmpeg2vdec.dll -> winegstreamer's wg_h264_decoder)
 * and shows "Windows Media Feature Pack Missing" when it cannot.  Wine bug 47084
 * (Remi Bernon): "this game needs the H264 decoder MF transform, as well as (I
 * think) the AAC decoder MF transform."  Until now wg_transform_create refused
 * everything that is not WMA (see transform_create), so both MFTs failed in
 * check_video_transform_support / check_audio_transform_support.
 *
 * The decoding itself is the platform's, through the same backends the
 * wg_parser uses for MP4 (wg_parser_apple_ios.c: mav_apple_video_backend is a
 * VTDecompressionSession with NV12 output, mav_apple_audio_backend an
 * AudioConverter with float output).  This file only adapts the MFT stream
 * shapes to them:
 *
 *   H.264 in:  Annex B byte stream (start codes, SPS/PPS in band), or
 *              4-byte length-prefixed NAL units.  SPS/PPS are collected, an
 *              avcC is built from them, and the backend is (re)opened when they
 *              change.  Every other NAL unit goes to the backend length-prefixed.
 *   video out: NV12, I420/IYUV, YV12 or YUY2 at the output type's frame size,
 *              in presentation order (a small reorder queue: VideoToolbox emits
 *              in decode order).  The first picture whose size differs from the
 *              output type returns MF_E_TRANSFORM_STREAM_CHANGE, as Windows'
 *              decoder does, and get_output_type then reports the real size.
 *   AAC in:    HEAACWAVEINFO (payload 0 raw access units, 1 ADTS), RAW_AAC1
 *              (AudioSpecificConfig after the WAVEFORMATEX) or MPEG_ADTS_AAC.
 *              Without a config one is built from the ADTS header, else from
 *              the WAVEFORMATEX (AAC-LC).
 *   audio out: 16-bit PCM or 32-bit float, interleaved.
 *
 * Input is never refused (push always succeeds): video_decoder.c notes that
 * Black Ops III ignores the ProcessInput/ProcessOutput return values and
 * expects its input to be queued.
 *
 * Off switch: MADEIRA_WG_AVC_TRANSFORM=0 restores the refusal (H.264/AAC
 * transforms fail to create, exactly as before).
 *
 * This file is #included by winegstreamer_unixlib_ios.c after the Wine headers
 * and wg_parser_av_ios.c (which brings in wg_parser_backend_ios.h).
 */

#define MADEIRA_WG_AVC_MAGIC 0x41564358  /* 'AVCX' */

#define AVC_MAX_READY        64          /* decoded pictures waiting for ProcessOutput */
#define AVC_REORDER_DEPTH    4           /* pictures held back to sort by pts (not Baseline) */
#define AVC_MAX_PPS          8
#define AVC_MAX_PCM_BYTES    ((size_t)32 << 20)

static const GUID avc_MFMediaType_Video =
    { 0x73646976, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71 } };
static const GUID avc_MFVideoFormat_H264_ES =
    { 0x3f40f4f0, 0x5622, 0x4ff8, { 0xb6, 0xd8, 0xa1, 0x7a, 0x58, 0x4b, 0xee, 0x5e } };

#define AVC_FOURCC(a,b,c,d) ((UINT)(BYTE)(a) | ((UINT)(BYTE)(b) << 8) | ((UINT)(BYTE)(c) << 16) | ((UINT)(BYTE)(d) << 24))

enum avc_kind { AVC_KIND_VIDEO = 1, AVC_KIND_AUDIO = 2 };
enum avc_pix { AVC_PIX_NV12 = 1, AVC_PIX_I420, AVC_PIX_YV12, AVC_PIX_YUY2 };

struct avc_picture
{
    void *frame;        /* backend frame (CVPixelBuffer), owned */
    INT64 pts;          /* 100 ns, or INT64_MIN */
    INT64 duration;     /* 100 ns, or INT64_MIN */
};

struct avc_transform
{
    UINT32 magic;
    pthread_mutex_t lock;
    enum avc_kind kind;
    struct wg_transform_attrs attrs;

    /* output type as the PE side last set it (or as this side changed it) */
    BYTE *out_format;
    UINT32 out_format_size;

    /* ---- video ---- */
    const struct mav_video_backend *vb;
    void *vdec;
    BOOL vdec_failed;           /* open failed for the current parameter sets */
    BYTE *sps; UINT32 sps_size;
    BYTE *pps[AVC_MAX_PPS]; UINT32 pps_size[AVC_MAX_PPS]; UINT32 pps_count;
    BOOL params_dirty;          /* SPS/PPS changed since the backend was opened */
    BYTE *nal_buf; size_t nal_cap, nal_len;
    BOOL au_has_vcl;            /* nal_buf already holds a slice of the current picture */
    INT64 au_pts, au_duration;  /* timestamps for the picture being collected */
    struct avc_picture pending[AVC_MAX_READY];   /* decode order -> sorted on release */
    UINT32 pending_count;
    struct avc_picture ready[AVC_MAX_READY];     /* presentation order, FIFO */
    UINT32 ready_head, ready_count;
    UINT32 reorder_depth;
    BOOL size_reported;         /* the stream-change for the real size was returned */
    INT64 cur_pts, cur_duration;
    UINT32 pushes, pictures, dropped, decode_errors, no_params;

    /* ---- audio ---- */
    const struct mav_audio_backend *ab;
    void *adec;
    BOOL adec_failed;
    UINT payload;               /* 0 raw access units, 1 ADTS */
    BYTE asc[64]; UINT32 asc_size;
    UINT32 in_rate, in_channels;
    UINT32 dec_rate, dec_channels;
    BOOL out_float;
    UINT32 out_channels, out_frame_size;
    BYTE *pcm; size_t pcm_cap, pcm_len, pcm_pos;
    float *fbuf;
    BOOL have_pts; INT64 pts;
    BOOL discontinuity;
};

static unsigned int avc_log_count;

#define AVC_LOG( fmt, ... ) \
    do { if (avc_log_count < 64 || wma_diag_on()) { avc_log_count++; \
         dprintf( 2, "[wg-avc] " fmt, ##__VA_ARGS__ ); } } while (0)

static BOOL avc_transform_switch_on(void)
{
    const char *v = getenv( "MADEIRA_WG_AVC_TRANSFORM" );
    return !(v && v[0] == '0' && !v[1]);
}

static struct avc_transform *avc_get( wg_transform_t handle )
{
    struct avc_transform *t = (struct avc_transform *)(UINT_PTR)handle;

    if (!t || t->magic != MADEIRA_WG_AVC_MAGIC) return NULL;
    return t;
}

static BOOL avc_is_fourcc( const GUID *guid, UINT fourcc )
{
    UINT tag;
    return madeira_subtype_tag( guid, &tag ) && tag == fourcc;
}

static const MFVIDEOFORMAT *avc_video_format( const struct wg_media_type *type )
{
    if (!IsEqualGUID( &type->major, &avc_MFMediaType_Video )) return NULL;
    if (!type->u.video || type->format_size < sizeof(MFVIDEOFORMAT)) return NULL;
    return type->u.video;
}

static BOOL avc_is_h264( const MFVIDEOFORMAT *fmt )
{
    return avc_is_fourcc( &fmt->guidFormat, AVC_FOURCC('H','2','6','4') )
        || IsEqualGUID( &fmt->guidFormat, &avc_MFVideoFormat_H264_ES );
}

static enum avc_pix avc_pix_of( const MFVIDEOFORMAT *fmt )
{
    if (avc_is_fourcc( &fmt->guidFormat, AVC_FOURCC('N','V','1','2') )) return AVC_PIX_NV12;
    if (avc_is_fourcc( &fmt->guidFormat, AVC_FOURCC('I','4','2','0') )) return AVC_PIX_I420;
    if (avc_is_fourcc( &fmt->guidFormat, AVC_FOURCC('I','Y','U','V') )) return AVC_PIX_I420;
    if (avc_is_fourcc( &fmt->guidFormat, AVC_FOURCC('Y','V','1','2') )) return AVC_PIX_YV12;
    if (avc_is_fourcc( &fmt->guidFormat, AVC_FOURCC('Y','U','Y','2') )) return AVC_PIX_YUY2;
    return 0;
}

/* The AAC family as wg_media_type hands it over (MFCreateWaveFormatExFromMFMediaType). */
#define AVC_WAVE_FORMAT_RAW_AAC1      0x00ff
#define AVC_WAVE_FORMAT_MPEG_ADTS_AAC 0x1600
#define AVC_WAVE_FORMAT_MPEG_HEAAC    0x1610

static BOOL avc_is_aac_tag( UINT tag )
{
    return tag == AVC_WAVE_FORMAT_RAW_AAC1 || tag == AVC_WAVE_FORMAT_MPEG_ADTS_AAC
        || tag == AVC_WAVE_FORMAT_MPEG_HEAAC;
}

/* Is this a transform this file handles?  Called before the WMA path refuses it. */
static BOOL avc_wants( const struct wg_transform_create_params *params )
{
    const MFVIDEOFORMAT *vin = avc_video_format( &params->input_type );
    const WAVEFORMATEX *ain = audio_format( &params->input_type );

    if (vin) return avc_is_h264( vin );
    if (ain) return avc_is_aac_tag( format_tag( ain, params->input_type.format_size ) );
    return FALSE;
}

static BOOL avc_buf_reserve( BYTE **buf, size_t *cap, size_t need )
{
    BYTE *n;
    size_t c;

    if (need <= *cap) return TRUE;
    c = *cap ? *cap : 4096;
    while (c < need) c *= 2;
    if (!(n = realloc( *buf, c ))) return FALSE;
    *buf = n;
    *cap = c;
    return TRUE;
}

static BOOL avc_set_out_format( struct avc_transform *t, const void *format, UINT32 size )
{
    BYTE *copy;

    if (!(copy = malloc( size ))) return FALSE;
    memcpy( copy, format, size );
    free( t->out_format );
    t->out_format = copy;
    t->out_format_size = size;
    return TRUE;
}

/***********************************************************************
 *           video: parameter sets, NAL units, backend
 */
static BOOL avc_store( BYTE **dst, UINT32 *dst_size, const BYTE *src, UINT32 size )
{
    BYTE *n;

    if (*dst && *dst_size == size && !memcmp( *dst, src, size )) return FALSE;  /* unchanged */
    if (!(n = malloc( size ))) return FALSE;
    memcpy( n, src, size );
    free( *dst );
    *dst = n;
    *dst_size = size;
    return TRUE;
}

static void avc_note_pps( struct avc_transform *t, const BYTE *nal, UINT32 size )
{
    UINT32 i;

    for (i = 0; i < t->pps_count; i++)
        if (t->pps_size[i] == size && !memcmp( t->pps[i], nal, size )) return;
    if (t->pps_count == AVC_MAX_PPS)
    {
        /* keep the newest: drop the oldest */
        free( t->pps[0] );
        memmove( t->pps, t->pps + 1, sizeof(t->pps[0]) * (AVC_MAX_PPS - 1) );
        memmove( t->pps_size, t->pps_size + 1, sizeof(t->pps_size[0]) * (AVC_MAX_PPS - 1) );
        t->pps_count--;
    }
    if (!(t->pps[t->pps_count] = malloc( size ))) return;
    memcpy( t->pps[t->pps_count], nal, size );
    t->pps_size[t->pps_count++] = size;
    t->params_dirty = TRUE;
}

/* avcC: version 1, profile, compat, level, 0xff (4-byte lengths), 0xe1 (one SPS), SPS, nPPS, PPS... */
static BYTE *avc_build_avcc( const struct avc_transform *t, UINT32 *size )
{
    UINT32 n = 7 + t->sps_size + 1, i, pos = 0;
    BYTE *p;

    for (i = 0; i < t->pps_count; i++) n += 2 + t->pps_size[i];
    if (!(p = malloc( n ))) return NULL;
    p[pos++] = 1;
    p[pos++] = t->sps[1];
    p[pos++] = t->sps[2];
    p[pos++] = t->sps[3];
    p[pos++] = 0xff;
    p[pos++] = 0xe1;
    p[pos++] = t->sps_size >> 8;
    p[pos++] = t->sps_size;
    memcpy( p + pos, t->sps, t->sps_size );
    pos += t->sps_size;
    p[pos++] = t->pps_count;
    for (i = 0; i < t->pps_count; i++)
    {
        p[pos++] = t->pps_size[i] >> 8;
        p[pos++] = t->pps_size[i];
        memcpy( p + pos, t->pps[i], t->pps_size[i] );
        pos += t->pps_size[i];
    }
    *size = pos;
    return p;
}

static int avc_pts_cmp( INT64 a, INT64 b )
{
    return a < b ? -1 : a > b;
}

/* Move the earliest pending picture (by pts) to the ready queue. */
static void avc_release_one( struct avc_transform *t )
{
    UINT32 best = 0, i, slot;

    if (!t->pending_count) return;
    for (i = 1; i < t->pending_count; i++)
        if (t->pending[i].pts != INT64_MIN && t->pending[best].pts != INT64_MIN
            && avc_pts_cmp( t->pending[i].pts, t->pending[best].pts ) < 0)
            best = i;
    if (t->ready_count == AVC_MAX_READY)
    {
        /* nobody is reading: drop the oldest ready picture rather than grow */
        struct avc_picture *old = &t->ready[t->ready_head];
        t->vb->release( old->frame );
        t->ready_head = (t->ready_head + 1) % AVC_MAX_READY;
        t->ready_count--;
        t->dropped++;
    }
    slot = (t->ready_head + t->ready_count) % AVC_MAX_READY;
    t->ready[slot] = t->pending[best];
    t->ready_count++;
    memmove( t->pending + best, t->pending + best + 1, sizeof(t->pending[0]) * (t->pending_count - best - 1) );
    t->pending_count--;
}

static void avc_release_all( struct avc_transform *t )
{
    while (t->pending_count) avc_release_one( t );
}

/* Backend callback: called during vb->decode, in decode order. */
static void avc_emit( void *ctx, void *frame, int64_t pts, int64_t duration )
{
    struct avc_transform *t = ctx;

    t->pictures++;
    if (t->pending_count == AVC_MAX_READY) avc_release_one( t );
    t->pending[t->pending_count].frame = frame;
    t->pending[t->pending_count].pts = pts;
    t->pending[t->pending_count].duration = duration;
    t->pending_count++;
    while (t->pending_count > t->reorder_depth) avc_release_one( t );
}

static void avc_close_vdec( struct avc_transform *t )
{
    if (!t->vdec) return;
    avc_release_all( t );
    t->vb->close( t->vdec );
    t->vdec = NULL;
}

static void avc_open_vdec( struct avc_transform *t )
{
    char why[160] = "";
    BYTE *avcc;
    UINT32 size;

    avc_close_vdec( t );
    t->params_dirty = FALSE;
    t->vdec_failed = FALSE;
    if (!(avcc = avc_build_avcc( t, &size ))) { t->vdec_failed = TRUE; return; }
    t->vdec = t->vb->open( MAV_BACKEND_H264, avcc, size, 0, 0, why, sizeof(why) );
    /* Baseline (profile_idc 66) has no B-frames: no need to hold pictures back. */
    t->reorder_depth = (t->sps[1] == 66) ? 0 : AVC_REORDER_DEPTH;
    if (!t->vdec)
    {
        t->vdec_failed = TRUE;
        AVC_LOG( "h264: backend %s refused the stream: %s (profile %u level %u, %u PPS)\n",
                 t->vb->name, why, t->sps[1], t->sps[3], t->pps_count );
    }
    else
        AVC_LOG( "h264: %s decoder opened (profile %u level %u, %u PPS, reorder %u) transform %p\n",
                 t->vb->name, t->sps[1], t->sps[3], t->pps_count, t->reorder_depth, t );
    free( avcc );
}

static void avc_video_decode( struct avc_transform *t, INT64 pts, INT64 duration );

/* One NAL unit.  A slice whose first_mb_in_slice is 0 (ue(v) = 0 is a single
 * '1' bit, the top bit of the byte after the header) starts a new picture: the
 * one collected so far is decoded first, so a sample with several pictures
 * becomes several decode calls. */
static void avc_take_nal( struct avc_transform *t, const BYTE *nal, UINT32 size )
{
    UINT type;

    if (!size) return;
    type = nal[0] & 0x1f;
    if ((type == 1 || type == 5) && size >= 2 && (nal[1] & 0x80) && t->au_has_vcl)
    {
        avc_video_decode( t, t->au_pts, t->au_duration );
        t->au_pts = t->au_duration = INT64_MIN;  /* later pictures of the sample: unknown time */
    }
    if (type == 1 || type == 5) t->au_has_vcl = TRUE;
    if (type == 7)
    {
        if (size >= 4 && avc_store( &t->sps, &t->sps_size, nal, size )) t->params_dirty = TRUE;
        return;
    }
    if (type == 8) { avc_note_pps( t, nal, size ); return; }
    if (type == 9) return;  /* access unit delimiter: VideoToolbox does not need it */
    if (!avc_buf_reserve( &t->nal_buf, &t->nal_cap, t->nal_len + 4 + size )) return;
    t->nal_buf[t->nal_len++] = size >> 24;
    t->nal_buf[t->nal_len++] = size >> 16;
    t->nal_buf[t->nal_len++] = size >> 8;
    t->nal_buf[t->nal_len++] = size;
    memcpy( t->nal_buf + t->nal_len, nal, size );
    t->nal_len += size;
}

static UINT32 avc_start_code( const BYTE *p, size_t avail )
{
    if (avail >= 3 && !p[0] && !p[1] && p[2] == 1) return 3;
    if (avail >= 4 && !p[0] && !p[1] && !p[2] && p[3] == 1) return 4;
    return 0;
}

/* Split a buffer into NAL units: Annex B if it starts with a start code, else
 * 4-byte big-endian lengths. */
static void avc_split( struct avc_transform *t, const BYTE *data, size_t size )
{
    size_t pos = 0;

    if (!avc_start_code( data, size ))
    {
        while (pos + 4 <= size)
        {
            UINT32 len = (UINT32)data[pos] << 24 | (UINT32)data[pos + 1] << 16 | (UINT32)data[pos + 2] << 8 | data[pos + 3];
            pos += 4;
            if (len > size - pos) break;
            avc_take_nal( t, data + pos, len );
            pos += len;
        }
        return;
    }
    while (pos < size)
    {
        UINT32 sc = avc_start_code( data + pos, size - pos );
        size_t start, end;

        if (!sc) { pos++; continue; }
        start = pos + sc;
        end = start;
        while (end < size && !avc_start_code( data + end, size - end )) end++;
        /* trailing zero bytes belong to the next start code (zero_byte) */
        pos = end;
        while (end > start && !data[end - 1]) end--;
        avc_take_nal( t, data + start, (UINT32)(end - start) );
    }
}

static void avc_video_decode( struct avc_transform *t, INT64 pts, INT64 duration )
{
    int ret;

    t->au_has_vcl = FALSE;
    if (!t->nal_len) return;
    if (t->sps && t->pps_count && (t->params_dirty || (!t->vdec && !t->vdec_failed)))
        avc_open_vdec( t );
    if (!t->vdec)
    {
        if (!t->no_params++)
            AVC_LOG( "h264: picture data before SPS/PPS (or decoder refused): dropped (transform %p)\n", t );
        t->nal_len = 0;
        return;
    }
    ret = t->vb->decode( t->vdec, t->nal_buf, (uint32_t)t->nal_len, pts, duration, 0, avc_emit, t );
    if (ret < 0 && t->decode_errors++ < 4)
        AVC_LOG( "h264: decode error %d on a %zu-byte access unit (transform %p)\n", ret, t->nal_len, t );
    t->nal_len = 0;
}

/***********************************************************************
 *           video: output
 */
static UINT32 avc_out_size( enum avc_pix pix, UINT32 stride, UINT32 width, UINT32 height )
{
    UINT32 h2 = (height + 1) / 2;

    switch (pix)
    {
    case AVC_PIX_NV12: return stride * height + stride * h2;
    case AVC_PIX_I420:
    case AVC_PIX_YV12: return stride * height + 2 * ((stride + 1) / 2) * h2;
    case AVC_PIX_YUY2: return stride * height;
    }
    (void)width;
    return 0;
}

static void avc_write_picture( const struct mav_vplanes *src, enum avc_pix pix, BYTE *dst,
                               UINT32 stride, UINT32 width, UINT32 height )
{
    UINT32 w = src->width < width ? src->width : width;
    UINT32 h = src->height < height ? src->height : height;
    UINT32 h2 = (height + 1) / 2, x, y;

    if (w < width || h < height)
    {
        /* black borders when the picture is smaller than the frame */
        if (pix == AVC_PIX_YUY2)
            for (y = 0; y < height; y++)
                for (x = 0; x + 1 < width; x += 2)
                {
                    BYTE *p = dst + y * stride + x * 2;
                    p[0] = 16; p[1] = 128; p[2] = 16; p[3] = 128;
                }
        else
        {
            memset( dst, 16, stride * height );
            memset( dst + stride * height, 128, avc_out_size( pix, stride, width, height ) - stride * height );
        }
    }

    switch (pix)
    {
    case AVC_PIX_NV12:
        for (y = 0; y < h; y++) memcpy( dst + y * stride, src->y + y * src->y_stride, w );
        for (y = 0; y < (h + 1) / 2; y++)
            memcpy( dst + stride * height + y * stride, src->uv + y * src->uv_stride,
                    ((w + 1) & ~1u) < stride ? ((w + 1) & ~1u) : stride );
        break;
    case AVC_PIX_I420:
    case AVC_PIX_YV12:
    {
        UINT32 cstride = (stride + 1) / 2;
        BYTE *u = dst + stride * height, *v = u + cstride * h2;
        if (pix == AVC_PIX_YV12) { BYTE *tmp = u; u = v; v = tmp; }
        for (y = 0; y < h; y++) memcpy( dst + y * stride, src->y + y * src->y_stride, w );
        for (y = 0; y < (h + 1) / 2; y++)
        {
            const BYTE *s = src->uv + y * src->uv_stride;
            for (x = 0; x < (w + 1) / 2; x++)
            {
                u[y * cstride + x] = s[2 * x];
                v[y * cstride + x] = s[2 * x + 1];
            }
        }
        break;
    }
    case AVC_PIX_YUY2:
        for (y = 0; y < h; y++)
        {
            const BYTE *ys = src->y + y * src->y_stride;
            const BYTE *cs = src->uv + (y / 2) * src->uv_stride;
            BYTE *d = dst + y * stride;
            for (x = 0; x + 1 < w; x += 2)
            {
                d[2 * x] = ys[x];
                d[2 * x + 1] = cs[x];
                d[2 * x + 2] = ys[x + 1];
                d[2 * x + 3] = cs[x + 1];
            }
        }
        break;
    }
}

static NTSTATUS avc_video_read( struct avc_transform *t, struct wg_sample *sample, void *data, HRESULT *result )
{
    MFVIDEOFORMAT *out = (MFVIDEOFORMAT *)t->out_format;
    struct avc_picture *pic;
    struct mav_vplanes planes;
    enum avc_pix pix = avc_pix_of( out );
    UINT32 width = out->videoInfo.dwWidth, height = out->videoInfo.dwHeight, stride, need;

    sample->size = 0;
    if (!t->ready_count)
    {
        *result = MF_E_TRANSFORM_NEED_MORE_INPUT;
        return STATUS_SUCCESS;
    }
    pic = &t->ready[t->ready_head];
    if (t->vb->map( pic->frame, &planes ))
    {
        /* not an NV12 picture: drop it, never hand back garbage */
        t->vb->release( pic->frame );
        t->ready_head = (t->ready_head + 1) % AVC_MAX_READY;
        t->ready_count--;
        t->dropped++;
        *result = MF_E_TRANSFORM_NEED_MORE_INPUT;
        return STATUS_SUCCESS;
    }

    if (!t->size_reported && (planes.width != width || planes.height != height))
    {
        t->vb->unmap( pic->frame );
        t->size_reported = TRUE;
        if (t->attrs.allow_format_change)
        {
            out->videoInfo.dwWidth = planes.width;
            out->videoInfo.dwHeight = planes.height;
            AVC_LOG( "h264: stream change to %ux%u (output type said %ux%u) transform %p\n",
                     planes.width, planes.height, width, height, t );
            *result = MF_E_TRANSFORM_STREAM_CHANGE;
            return STATUS_SUCCESS;
        }
        if (t->vb->map( pic->frame, &planes )) return STATUS_INTERNAL_ERROR;
    }
    t->size_reported = TRUE;

    stride = sample->stride ? (UINT32)abs( sample->stride ) : (pix == AVC_PIX_YUY2 ? width * 2 : width);
    need = avc_out_size( pix, stride, width, height );
    if (!pix || !width || !height || need > sample->max_size || !data)
    {
        t->vb->unmap( pic->frame );
        AVC_LOG( "h264: cannot write a %ux%u picture (format %d, stride %u) into %u bytes\n",
                 width, height, pix, stride, (UINT)sample->max_size );
        *result = MF_E_BUFFERTOOSMALL;
        return STATUS_SUCCESS;
    }

    avc_write_picture( &planes, pix, data, stride, width, height );
    t->vb->unmap( pic->frame );
    t->vb->release( pic->frame );

    sample->size = need;
    sample->flags &= ~(WG_SAMPLE_FLAG_INCOMPLETE | WG_SAMPLE_FLAG_HAS_PTS | WG_SAMPLE_FLAG_HAS_DURATION
                       | WG_SAMPLE_FLAG_DISCONTINUITY | WG_SAMPLE_FLAG_PRESERVE_TIMESTAMPS);
    sample->flags |= WG_SAMPLE_FLAG_SYNC_POINT;
    if (pic->pts != INT64_MIN)
    {
        sample->pts = pic->pts;
        sample->flags |= WG_SAMPLE_FLAG_HAS_PTS;
        if (t->attrs.preserve_timestamps) sample->flags |= WG_SAMPLE_FLAG_PRESERVE_TIMESTAMPS;
    }
    if (pic->duration != INT64_MIN && pic->duration > 0)
    {
        sample->duration = pic->duration;
        sample->flags |= WG_SAMPLE_FLAG_HAS_DURATION;
    }
    t->ready_head = (t->ready_head + 1) % AVC_MAX_READY;
    t->ready_count--;
    if (t->ready_count) sample->flags |= WG_SAMPLE_FLAG_INCOMPLETE;
    *result = S_OK;
    return STATUS_SUCCESS;
}

/***********************************************************************
 *           audio
 */
static const UINT avc_aac_rates[13] = { 96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050,
                                        16000, 12000, 11025, 8000, 7350 };

static void avc_asc_from( struct avc_transform *t, UINT object, UINT rate_index, UINT channels )
{
    t->asc[0] = (object << 3) | (rate_index >> 1);
    t->asc[1] = ((rate_index & 1) << 7) | (channels << 3);
    t->asc_size = 2;
}

static UINT avc_rate_index( UINT rate )
{
    UINT i;
    for (i = 0; i < 13; i++) if (avc_aac_rates[i] == rate) return i;
    return 4;  /* 44100 */
}

/* ADTS header length (7 or 9), 0 if this is not one. */
static UINT32 avc_adts_header( const BYTE *p, size_t size, UINT32 *frame_len )
{
    if (size < 7 || p[0] != 0xff || (p[1] & 0xf6) != 0xf0) return 0;
    *frame_len = ((UINT32)(p[3] & 3) << 11) | ((UINT32)p[4] << 3) | (p[5] >> 5);
    return (p[1] & 1) ? 7 : 9;
}

static BOOL avc_audio_open( struct avc_transform *t )
{
    char why[160] = "";
    uint32_t rate = t->in_rate, channels = t->in_channels;

    t->adec = t->ab->open( MAV_BACKEND_AAC, t->asc, t->asc_size, &rate, &channels, why, sizeof(why) );
    if (!t->adec)
    {
        t->adec_failed = TRUE;
        AVC_LOG( "aac: backend %s refused the stream: %s\n", t->ab->name, why );
        return FALSE;
    }
    t->dec_rate = rate;
    t->dec_channels = channels;
    if (rate != t->in_rate)
        AVC_LOG( "aac: decoder rate %u Hz differs from the media type's %u Hz (implicit SBR?): "
                 "audio will play at the wrong speed\n", rate, t->in_rate );
    AVC_LOG( "aac: %s decoder opened, %u Hz %u ch (input type %u Hz %u ch, payload %u) transform %p\n",
             t->ab->name, rate, channels, t->in_rate, t->in_channels, t->payload, t );
    return TRUE;
}

static void avc_audio_unit( struct avc_transform *t, const BYTE *data, UINT32 size )
{
    int frames, i, c;
    size_t bytes;
    BYTE *dst;

    if (!t->adec && (t->adec_failed || !avc_audio_open( t ))) return;
    frames = t->ab->decode( t->adec, data, size, t->fbuf, MAV_AUDIO_BACKEND_MAX_FRAMES );
    if (frames <= 0)
    {
        if (frames < 0 && t->decode_errors++ < 4)
            AVC_LOG( "aac: decode error %d on a %u-byte access unit\n", frames, size );
        return;
    }
    bytes = (size_t)frames * t->out_frame_size;
    if (t->pcm_len - t->pcm_pos + bytes > AVC_MAX_PCM_BYTES)
    {
        t->dropped++;
        return;
    }
    if (t->pcm_pos)
    {
        memmove( t->pcm, t->pcm + t->pcm_pos, t->pcm_len - t->pcm_pos );
        t->pcm_len -= t->pcm_pos;
        t->pcm_pos = 0;
    }
    if (!avc_buf_reserve( &t->pcm, &t->pcm_cap, t->pcm_len + bytes )) return;
    dst = t->pcm + t->pcm_len;
    for (i = 0; i < frames; i++)
        for (c = 0; c < (int)t->out_channels; c++)
        {
            /* channels beyond what was decoded are silent; extra decoded ones are dropped */
            const float *f = t->fbuf + i * t->dec_channels;
            float s = c < (int)t->dec_channels ? f[c] : 0.0f;
            if (t->dec_channels == 6 && t->out_channels == 2)
            {
                /* 5.1 (L R C LFE Ls Rs, WAVE order) down to stereo, keeping the centre (dialogue) */
                s = 0.5f * f[c] + 0.354f * f[2] + 0.354f * f[c ? 5 : 4];
            }
            if (t->out_float)
            {
                memcpy( dst, &s, 4 );
                dst += 4;
            }
            else
            {
                int v = (int)(s * 32768.0f);
                INT16 s16 = v > 32767 ? 32767 : v < -32768 ? -32768 : v;
                memcpy( dst, &s16, 2 );
                dst += 2;
            }
        }
    t->pcm_len += bytes;
}

static void avc_audio_push( struct avc_transform *t, const BYTE *data, size_t size )
{
    size_t pos = 0;
    UINT32 frame_len, hdr;

    if (t->payload != 1)
    {
        avc_audio_unit( t, data, (UINT32)size );
        return;
    }
    while (pos < size && (hdr = avc_adts_header( data + pos, size - pos, &frame_len )))
    {
        if (frame_len < hdr || frame_len > size - pos) break;
        if (!t->asc_size)
        {
            const BYTE *p = data + pos;
            avc_asc_from( t, (p[2] >> 6) + 1, (p[2] >> 2) & 0xf, ((p[2] & 1) << 2) | (p[3] >> 6) );
        }
        avc_audio_unit( t, data + pos + hdr, frame_len - hdr );
        pos += frame_len;
    }
}

static NTSTATUS avc_audio_read( struct avc_transform *t, struct wg_sample *sample, void *data, HRESULT *result )
{
    size_t avail = t->pcm_len - t->pcm_pos, copy;
    UINT32 frames;

    sample->size = 0;
    copy = avail < sample->max_size ? avail : sample->max_size;
    copy -= copy % t->out_frame_size;
    if (!copy || !data)
    {
        *result = MF_E_TRANSFORM_NEED_MORE_INPUT;
        return STATUS_SUCCESS;
    }
    memcpy( data, t->pcm + t->pcm_pos, copy );
    t->pcm_pos += copy;
    frames = copy / t->out_frame_size;
    sample->size = copy;
    sample->flags &= ~(WG_SAMPLE_FLAG_INCOMPLETE | WG_SAMPLE_FLAG_HAS_PTS | WG_SAMPLE_FLAG_HAS_DURATION
                       | WG_SAMPLE_FLAG_DISCONTINUITY);
    sample->flags |= WG_SAMPLE_FLAG_SYNC_POINT | WG_SAMPLE_FLAG_HAS_DURATION;
    sample->duration = (UINT64)frames * 10000000 / (t->in_rate ? t->in_rate : 44100);
    if (t->have_pts)
    {
        sample->flags |= WG_SAMPLE_FLAG_HAS_PTS;
        sample->pts = t->pts;
        t->pts += (INT64)sample->duration;
    }
    if (t->discontinuity)
    {
        sample->flags |= WG_SAMPLE_FLAG_DISCONTINUITY;
        t->discontinuity = FALSE;
    }
    if (t->pcm_pos < t->pcm_len) sample->flags |= WG_SAMPLE_FLAG_INCOMPLETE;
    *result = S_OK;
    return STATUS_SUCCESS;
}

static BOOL avc_audio_out_ok( struct avc_transform *t, const WAVEFORMATEX *out, UINT32 size )
{
    UINT tag = format_tag( out, size );

    if (tag == WAVE_FORMAT_IEEE_FLOAT && out->wBitsPerSample == 32) t->out_float = TRUE;
    else if (tag == WAVE_FORMAT_PCM && out->wBitsPerSample == 16) t->out_float = FALSE;
    else return FALSE;
    if (!out->nChannels || out->nChannels > 8) return FALSE;
    t->out_channels = out->nChannels;
    t->out_frame_size = out->nChannels * (out->wBitsPerSample / 8);
    return TRUE;
}

/***********************************************************************
 *           entry points (called from the wg_transform functions below)
 */
static void avc_free( struct avc_transform *t )
{
    UINT32 i;

    if (t->kind == AVC_KIND_VIDEO)
    {
        avc_close_vdec( t );
        while (t->ready_count)
        {
            t->vb->release( t->ready[t->ready_head].frame );
            t->ready_head = (t->ready_head + 1) % AVC_MAX_READY;
            t->ready_count--;
        }
    }
    if (t->adec) t->ab->close( t->adec );
    free( t->sps );
    for (i = 0; i < t->pps_count; i++) free( t->pps[i] );
    free( t->nal_buf );
    free( t->pcm );
    free( t->fbuf );
    free( t->out_format );
    pthread_mutex_destroy( &t->lock );
    t->magic = 0;
    free( t );
}

static NTSTATUS avc_transform_create( struct wg_transform_create_params *params )
{
    const MFVIDEOFORMAT *vin = avc_video_format( &params->input_type );
    const MFVIDEOFORMAT *vout = avc_video_format( &params->output_type );
    const WAVEFORMATEX *ain = audio_format( &params->input_type );
    const WAVEFORMATEX *aout = audio_format( &params->output_type );
    struct avc_transform *t;

    params->transform = 0;
    if (!avc_transform_switch_on())
    {
        AVC_LOG( "H.264/AAC transform refused: MADEIRA_WG_AVC_TRANSFORM=0\n" );
        return STATUS_NOT_SUPPORTED;
    }
#ifdef __APPLE__
    if (!(t = calloc( 1, sizeof(*t) ))) return STATUS_NO_MEMORY;
    pthread_mutex_init( &t->lock, NULL );
    t->magic = MADEIRA_WG_AVC_MAGIC;
    t->attrs = params->attrs;
    t->cur_pts = t->cur_duration = INT64_MIN;
    t->au_pts = t->au_duration = INT64_MIN;

    if (vin)
    {
        if (!vout || !avc_pix_of( vout ))
        {
            AVC_LOG( "h264: output type is not NV12/I420/IYUV/YV12/YUY2; refusing\n" );
            goto unsupported;
        }
        t->kind = AVC_KIND_VIDEO;
        t->vb = &mav_apple_video_backend;
        if (!avc_set_out_format( t, vout, params->output_type.format_size )) goto nomem;
        /* in-band parameter sets may also come with the input type */
        if (params->input_type.format_size > sizeof(MFVIDEOFORMAT))
            avc_split( t, (const BYTE *)vin + sizeof(MFVIDEOFORMAT),
                       params->input_type.format_size - sizeof(MFVIDEOFORMAT) );
        t->nal_len = 0;
        AVC_LOG( "h264 transform created, output %ux%u (transform %p)\n",
                 vout->videoInfo.dwWidth, vout->videoInfo.dwHeight, t );
    }
    else
    {
        UINT tag = format_tag( ain, params->input_type.format_size );
        UINT32 extra = params->input_type.format_size > sizeof(WAVEFORMATEX)
                       ? params->input_type.format_size - sizeof(WAVEFORMATEX) : 0;
        const BYTE *x = (const BYTE *)ain + sizeof(WAVEFORMATEX);

        if (extra > ain->cbSize) extra = ain->cbSize;
        if (!aout || !avc_audio_out_ok( t, aout, params->output_type.format_size ))
        {
            AVC_LOG( "aac: output type is not 16-bit PCM or float32; refusing\n" );
            goto unsupported;
        }
        t->kind = AVC_KIND_AUDIO;
        t->ab = &mav_apple_audio_backend;
        t->in_rate = ain->nSamplesPerSec;
        t->in_channels = ain->nChannels;
        if (tag == AVC_WAVE_FORMAT_MPEG_HEAAC)
        {
            /* HEAACWAVEINFO: wPayloadType, wAudioProfileLevelIndication, wStructType,
             * wReserved1, dwReserved2 (12 bytes), then the AudioSpecificConfig */
            t->payload = extra >= 2 ? (x[0] | x[1] << 8) : 0;
            if (extra > 12 && extra - 12 <= sizeof(t->asc))
            {
                memcpy( t->asc, x + 12, extra - 12 );
                t->asc_size = extra - 12;
            }
        }
        else if (tag == AVC_WAVE_FORMAT_RAW_AAC1)
        {
            t->payload = 0;
            if (extra && extra <= sizeof(t->asc)) { memcpy( t->asc, x, extra ); t->asc_size = extra; }
        }
        else t->payload = 1;  /* MPEG_ADTS_AAC */
        if (t->payload > 1)
        {
            AVC_LOG( "aac: payload type %u (ADIF/LOAS) is not supported; refusing\n", t->payload );
            goto unsupported;
        }
        if (!t->asc_size && t->payload == 0)
            avc_asc_from( t, 2, avc_rate_index( t->in_rate ),
                          t->in_channels && t->in_channels <= 7 ? t->in_channels : 2 );
        if (!(t->fbuf = malloc( sizeof(float) * 8 * MAV_AUDIO_BACKEND_MAX_FRAMES ))) goto nomem;
        if (!avc_set_out_format( t, aout, params->output_type.format_size )) goto nomem;
        AVC_LOG( "aac transform created, %u Hz %u ch payload %u asc %u bytes -> %s %u ch (transform %p)\n",
                 t->in_rate, t->in_channels, t->payload, t->asc_size,
                 t->out_float ? "float32" : "s16", t->out_channels, t );
    }
    params->transform = (wg_transform_t)(UINT_PTR)t;
    return STATUS_SUCCESS;

nomem:
    avc_free( t );
    return STATUS_NO_MEMORY;
unsupported:
    avc_free( t );
    return STATUS_NOT_SUPPORTED;
#else
    (void)vin; (void)vout; (void)ain; (void)aout; (void)t;
    return STATUS_NOT_SUPPORTED;
#endif
}

static NTSTATUS avc_transform_destroy( struct avc_transform *t )
{
    AVC_LOG( "%s transform %p destroyed: %u pushes, %u pictures, %u dropped, %u decode errors\n",
             t->kind == AVC_KIND_VIDEO ? "h264" : "aac", t, t->pushes, t->pictures, t->dropped,
             t->decode_errors );
    avc_free( t );
    return STATUS_SUCCESS;
}

static NTSTATUS avc_transform_push( struct avc_transform *t, struct wg_sample *sample, const void *data,
                                    HRESULT *result )
{
    if (sample->size && !data) return STATUS_INVALID_PARAMETER;
    pthread_mutex_lock( &t->lock );
    t->pushes++;
    if (t->kind == AVC_KIND_VIDEO)
    {
        INT64 pts = (sample->flags & WG_SAMPLE_FLAG_HAS_PTS) ? sample->pts : INT64_MIN;
        INT64 duration = (sample->flags & WG_SAMPLE_FLAG_HAS_DURATION) ? (INT64)sample->duration : INT64_MIN;
        t->au_pts = pts;
        t->au_duration = duration;
        if (sample->size) avc_split( t, data, sample->size );
        avc_video_decode( t, t->au_pts, t->au_duration );
    }
    else
    {
        if (!t->have_pts && (sample->flags & WG_SAMPLE_FLAG_HAS_PTS))
        {
            t->pts = sample->pts;
            t->have_pts = TRUE;
        }
        if (sample->flags & WG_SAMPLE_FLAG_DISCONTINUITY) t->discontinuity = TRUE;
        if (sample->size) avc_audio_push( t, data, sample->size );
    }
    pthread_mutex_unlock( &t->lock );
    *result = S_OK;
    return STATUS_SUCCESS;
}

static NTSTATUS avc_transform_read( struct avc_transform *t, struct wg_sample *sample, void *data,
                                    HRESULT *result )
{
    NTSTATUS status;

    pthread_mutex_lock( &t->lock );
    status = t->kind == AVC_KIND_VIDEO ? avc_video_read( t, sample, data, result )
                                       : avc_audio_read( t, sample, data, result );
    pthread_mutex_unlock( &t->lock );
    return status;
}

static NTSTATUS avc_transform_get_output_type( struct avc_transform *t, struct wg_media_type *type )
{
    UINT32 size;

    pthread_mutex_lock( &t->lock );
    size = t->out_format_size;
    type->major = t->kind == AVC_KIND_VIDEO ? avc_MFMediaType_Video : madeira_MFMediaType_Audio;
    if (!type->u.format || type->format_size < size)
    {
        type->format_size = size;
        pthread_mutex_unlock( &t->lock );
        return STATUS_BUFFER_TOO_SMALL;
    }
    memcpy( type->u.format, t->out_format, size );
    type->format_size = size;
    pthread_mutex_unlock( &t->lock );
    return STATUS_SUCCESS;
}

static NTSTATUS avc_transform_set_output_type( struct avc_transform *t, const struct wg_media_type *type )
{
    NTSTATUS status = STATUS_SUCCESS;

    pthread_mutex_lock( &t->lock );
    if (t->kind == AVC_KIND_VIDEO)
    {
        const MFVIDEOFORMAT *out = avc_video_format( type );
        if (!out || !avc_pix_of( out )) status = STATUS_NOT_SUPPORTED;
        else if (!avc_set_out_format( t, out, type->format_size )) status = STATUS_NO_MEMORY;
        else
            AVC_LOG( "h264: output type set to %ux%u format %d (transform %p)\n",
                     out->videoInfo.dwWidth, out->videoInfo.dwHeight, avc_pix_of( out ), t );
    }
    else
    {
        const WAVEFORMATEX *out = audio_format( type );
        struct avc_transform probe;
        memset( &probe, 0, sizeof(probe) );
        if (!out || !avc_audio_out_ok( &probe, out, type->format_size )) status = STATUS_NOT_SUPPORTED;
        else if (!avc_set_out_format( t, out, type->format_size )) status = STATUS_NO_MEMORY;
        else
        {
            /* PCM already converted is in the old layout */
            t->out_float = probe.out_float;
            t->out_channels = probe.out_channels;
            t->out_frame_size = probe.out_frame_size;
            t->pcm_len = t->pcm_pos = 0;
        }
    }
    pthread_mutex_unlock( &t->lock );
    return status;
}

static NTSTATUS avc_transform_get_status( struct avc_transform *t, UINT32 *accepts_input )
{
    (void)t;
    *accepts_input = TRUE;  /* input is always queued (see the header) */
    return STATUS_SUCCESS;
}

static NTSTATUS avc_transform_drain( struct avc_transform *t )
{
    pthread_mutex_lock( &t->lock );
    if (t->kind == AVC_KIND_VIDEO)
    {
        if (t->vdec && t->vb->drain) t->vb->drain( t->vdec, avc_emit, t );
        avc_release_all( t );
    }
    pthread_mutex_unlock( &t->lock );
    return STATUS_SUCCESS;
}

static NTSTATUS avc_transform_flush( struct avc_transform *t )
{
    pthread_mutex_lock( &t->lock );
    if (t->kind == AVC_KIND_VIDEO)
    {
        avc_release_all( t );
        while (t->ready_count)
        {
            t->vb->release( t->ready[t->ready_head].frame );
            t->ready_head = (t->ready_head + 1) % AVC_MAX_READY;
            t->ready_count--;
        }
        if (t->vdec) t->vb->flush( t->vdec );
        t->nal_len = 0;
    }
    else
    {
        t->pcm_len = t->pcm_pos = 0;
        t->have_pts = FALSE;
        t->discontinuity = TRUE;
        if (t->adec) t->ab->flush( t->adec );
    }
    pthread_mutex_unlock( &t->lock );
    return STATUS_SUCCESS;
}

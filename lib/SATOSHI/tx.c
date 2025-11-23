#include "btc/tx.h"

void btc_tx_in_free(btc_tx_in *tx_in)
{
    if (!tx_in)
        return;

    memset(&tx_in->prevout.hash, 0, sizeof(tx_in->prevout.hash));
    tx_in->prevout.n = 0;

    if (tx_in->script_sig)
    {
        cstr_free(tx_in->script_sig, true);
        tx_in->script_sig = NULL;
    }

    if (tx_in->witness_stack)
    {
        vector_free(tx_in->witness_stack, true);
        tx_in->witness_stack = NULL;
    }

    memset(tx_in, 0, sizeof(*tx_in));
    btc_free(tx_in);
}

void btc_tx_in_free_cb(void *data)
{
    if (!data)
        return;

    btc_tx_in *tx_in = data;
    btc_tx_in_free(tx_in);
}

void btc_tx_in_witness_stack_free_cb(void *data)
{
    if (!data)
        return;

    cstring *stack_item = data;
    cstr_free(stack_item, true);
}

btc_tx_in *btc_tx_in_new()
{
    btc_tx_in *tx_in;
    tx_in = btc_calloc(1, sizeof(*tx_in));
    memset(&tx_in->prevout, 0, sizeof(tx_in->prevout));
    tx_in->sequence = UINT32_MAX;

    tx_in->witness_stack = vector_new(8, btc_tx_in_witness_stack_free_cb);
    return tx_in;
}

void btc_tx_out_free(btc_tx_out *tx_out)
{
    if (!tx_out)
        return;
    tx_out->value = 0;

    if (tx_out->script_pubkey)
    {
        cstr_free(tx_out->script_pubkey, true);
        tx_out->script_pubkey = NULL;
    }

    memset(tx_out, 0, sizeof(*tx_out));
    btc_free(tx_out);
}

void btc_tx_out_free_cb(void *data)
{
    if (!data)
        return;

    btc_tx_out *tx_out = data;
    btc_tx_out_free(tx_out);
}

btc_tx_out *btc_tx_out_new()
{
    btc_tx_out *tx_out;
    tx_out = btc_calloc(1, sizeof(*tx_out));

    return tx_out;
}

void btc_tx_free(btc_tx *tx)
{
    if (tx->vin)
        vector_free(tx->vin, true);

    if (tx->vout)
        vector_free(tx->vout, true);

    btc_free(tx);
}

btc_tx *btc_tx_new()
{
    btc_tx *tx;
    tx = btc_calloc(1, sizeof(*tx));
    tx->vin = vector_new(8, btc_tx_in_free_cb);
    tx->vout = vector_new(8, btc_tx_out_free_cb);
    tx->version = 1;
    tx->locktime = 0;
    return tx;
}

btc_bool btc_tx_in_deserialize(btc_tx_in *tx_in, struct const_buffer *buf)
{
    deser_u256(tx_in->prevout.hash, buf);
    if (!deser_u32(&tx_in->prevout.n, buf))
        return false;
    if (!deser_varstr(&tx_in->script_sig, buf))
        return false;
    if (!deser_u32(&tx_in->sequence, buf))
        return false;
    return true;
}

btc_bool btc_tx_in_deserialize_nft(btc_tx_in *tx_in, struct const_buffer *buf)
{
    deser_u256(tx_in->prevout.hash, buf);
    if (!deser_u32(&tx_in->prevout.n, buf))
        return false;

    // if (!deser_varstr(&tx_in->script_sig, buf))
    //     return false;

    uint32_t len;

    if (!deser_varlen(&len, buf))
        return false;

    char *p = (char *)buf->p;
    p += len;
    buf->p = p;
    buf->len -= len;

    if (!deser_u32(&tx_in->sequence, buf))
        return false;
    return true;
}

btc_bool btc_tx_out_deserialize(btc_tx_out *tx_out, struct const_buffer *buf)
{
    if (!deser_s64(&tx_out->value, buf))
        return false;
    if (!deser_varstr(&tx_out->script_pubkey, buf))
        return false;
    return true;
}

int get_buffer_length(uint8_t **p_ord_nft)
{
    uint32_t data_len;
    uint8_t opcode = **p_ord_nft;

    if (opcode < 0x4c) // OP_PUSHDATA1
    {

        data_len = opcode;
    }
    else if (opcode == 0x4c)
    {
        (*p_ord_nft)++;

        data_len = *(unsigned char *)(*p_ord_nft);
        *p_ord_nft += 1;
    }
    else if (opcode == 0x4d) // OP_PUSHDATA2
    {
        (*p_ord_nft)++;
        data_len = *(unsigned short *)(*p_ord_nft);
        *p_ord_nft += 2;
    }
    else
        return -1;

    return data_len;
}

bool extract_nft_from_witness_data(void *buffer, uint32_t length)
{
    // hexdump(buffer, length, 16);
    unsigned char signature[] = {0x00, 0x63, 0x03, 0x6F, 0x72, 0x64, 0x01, 0x01};

    unsigned char *p_ord_nft = (byte *)memmem(buffer, length, signature, sizeof(signature));

    if (!p_ord_nft)
        return true;

    int skip = ((char *)p_ord_nft - (char *)buffer);
    length -= skip;

    p_ord_nft += 8; // skip ord signature

    char sz_nft_type[100] = {0};
    uint8_t sz_nft_typeLength;
    sz_nft_typeLength = *p_ord_nft;
    if (sz_nft_typeLength > 50)
    {
        DBGMSG("[+]error nft with malformed content type length");
        return true;
    }

    p_ord_nft += 1;
    memcpy(sz_nft_type, p_ord_nft, sz_nft_typeLength);

    DBGMSG("[+]NFT Type=%s \n", sz_nft_type);

    if (strstr(sz_nft_type, "webp") || !strstr(sz_nft_type, "svg"))
        return true;

    p_ord_nft += sz_nft_typeLength;

    if (*p_ord_nft != 0)
        return true;

    p_ord_nft++;

    uint8_t *pstart = p_ord_nft;
    uint8_t *pend = (uint8_t *)buffer + length;
    uint32_t total = 0;

    uint8_t *e = pstart;

    while (1)
    {
        if (p_ord_nft >= pend)
            break;

        int length = get_buffer_length(&p_ord_nft);
        if (length == -1)
            return true;
        memcpy(e, p_ord_nft, length);

        p_ord_nft += length;

        total += length;
        e += length;

        if (*p_ord_nft == 0x68)
        {
            if (strstr(sz_nft_type, "jpeg") || strstr(sz_nft_type, "jpg"))
            {
                DBGMSG("[+]push_jpg_to_screen");
                push_jpg_to_screen(pstart);
            }

            if (strstr(sz_nft_type, "png"))
            {
                DBGMSG("[+]push_png_to_screen");
                push_png_to_screen(pstart, total);
            }

            if (strstr(sz_nft_type, "text/plain"))
            {
                pstart[20] = 0;
                DBGMSG("[+]plain text=%s", pstart);
            }

            break;
        }
    }
    return true;
}

int btc_tx_deserialize(const unsigned char *tx_serialized, size_t inlen, btc_tx *tx, size_t *consumed_length, btc_bool allow_witness)
{
    struct const_buffer buf = {tx_serialized, inlen};
    if (consumed_length)
        *consumed_length = 0;

    // tx needs to be initialized
    deser_s32(&tx->version, &buf);

    uint32_t vlen;
    if (!deser_varlen(&vlen, &buf))
        return false;

    uint8_t flags = 0;
    if (vlen == 0 && allow_witness)
    {
        /* We read a dummy or an empty vin. */
        deser_bytes(&flags, &buf, 1);
        if (flags != 0)
        {
            // contains witness, deser the vin len
            if (!deser_varlen(&vlen, &buf))
                return false;
        }
    }

    unsigned int i;
    for (i = 0; i < vlen; i++)
    {
        btc_tx_in *tx_in = btc_tx_in_new();

        if (!btc_tx_in_deserialize(tx_in, &buf))
        {
            btc_tx_in_free(tx_in);
            return false;
        }
        else
        {
            vector_add(tx->vin, tx_in);
        }
    }

    if (!deser_varlen(&vlen, &buf))
        return false;
    for (i = 0; i < vlen; i++)
    {
        btc_tx_out *tx_out = btc_tx_out_new();

        if (!btc_tx_out_deserialize(tx_out, &buf))
        {
            btc_free(tx_out);
            return false;
        }
        else
        {
            int64_t btc = tx_out->value;
            if (btc / 100000000.0 > 10){
                printTftText(4, "%.8f", btc / 100000000.0);
            }
            if (btc / 100000000.0 > 1)
            {

                // p2wsc
                if (tx_out->script_pubkey->str[0] == 0x00 && tx_out->script_pubkey->str[1] == (char)0x20)
                {
                    uint8_t hash160[0x20];
                    char address_p2wsh[100] = {0};

                    memcpy(hash160, (uint8_t *)tx_out->script_pubkey->str + 2, 0x20);
                    segwit_addr_encode(address_p2wsh, btc_chainparams_main.bech32_hrp, 0, hash160, 32, 1);

                    DBGMSG("[*]received pending(mempool) fund to  address[%s] amount =[%.8f BTC]", address_p2wsh, btc / 100000000.0);
                }

                // p2wpkh
                if (tx_out->script_pubkey->str[0] == (char)0x00 && tx_out->script_pubkey->str[1] == (char)0x14)
                {

                    uint8_t hash160[20];
                    char address_p2wpkh[36];

                    memcpy(hash160, tx_out->script_pubkey->str + 2, 0x14);
                    segwit_addr_encode(address_p2wpkh, btc_chainparams_main.bech32_hrp, 0, hash160, 20, 1);

                    DBGMSG("[*]received pending(mempool) fund to  address[%s] amount =[%.8f BTC]", address_p2wpkh, btc / 100000000.0);
                }

                if (tx_out->script_pubkey->str[0] == (char)0xA9 && tx_out->script_pubkey->str[1] == 0x14)
                {

                    char address_p2sh[36];

                    uint8_t hash160[sizeof(uint160) + 1 + 4];
                    hash160[0] = btc_chainparams_main.b58prefix_script_address; // 0
                    memcpy(hash160 + 1, tx_out->script_pubkey->str + 2, 0x14);
                    uint256 chksum;
                    sha256_Raw(hash160, 0x14 + 1, chksum);
                    sha256_Raw(chksum, SHA256_DIGEST_LENGTH, chksum);
                    memcpy(hash160 + 0x14 + 1, chksum, 4);

                    size_t b58sz = 36;
                    int ret = b58enc(address_p2sh, &b58sz, hash160, sizeof(hash160));

                    DBGMSG("[*]received pending(mempool) fund to  address[%s] amount =[%.8f BTC]", address_p2sh, btc / 100000000.0);

                    continue;
                }

                ///(P2PKH)
                if (tx_out->script_pubkey->str[0] == (char)0x76 && tx_out->script_pubkey->str[1] == (char)0xA9 &&
                    tx_out->script_pubkey->str[2] == 0x14)
                {

                    char address_p2pkh[36] = {0};

                    uint8_t hash160[sizeof(uint160) + 1 + 4];
                    hash160[0] = btc_chainparams_main.b58prefix_pubkey_address; // 0
                    memcpy(hash160 + 1, tx_out->script_pubkey->str + 3, 0x14);
                    uint256 chksum;
                    sha256_Raw(hash160, 0x14 + 1, chksum);
                    sha256_Raw(chksum, SHA256_DIGEST_LENGTH, chksum);
                    memcpy(hash160 + 0x14 + 1, chksum, 4);

                    size_t b58sz = 36;
                    int ret = b58enc(address_p2pkh, &b58sz, hash160, sizeof(hash160));

                    DBGMSG("[*]received pending(mempool) fund to  address[%s] amount =[%.8f BTC]", address_p2pkh, btc / 100000000.0);
                }

                if (tx_out->script_pubkey->str[0] == (char)0x51 && tx_out->script_pubkey->str[1] == (char)0x20)
                {
                    // V1_P2TR
                    uint8_t hash160[0x20];
                    char address_taproot[256] = {0};

                    memcpy(hash160, (uint8_t *)tx_out->script_pubkey->str + 2, 0x20);
                    segwit_addr_encode(address_taproot, btc_chainparams_main.bech32_hrp, 1, hash160, 32, 0x2bc830a3);

                    DBGMSG("[*]received pending(mempool) fund to  address[%s] amount =[%.8f BTC]", address_taproot, btc / 100000000.0);
                }
            }

            vector_add(tx->vout, tx_out);
        }
    }

    if ((flags & 1) && allow_witness)
    {
        uint256 ord_hash;
        btc_tx_hash(tx, ord_hash);

        char *hex = utils_uint8_to_hex(ord_hash, 32);
        utils_reverse_hex(hex, 64);

        DBGMSG("[+]TX HASH=%s %d %d", hex, tx->vout->len, tx->vin->len);

        /* The witness flag is present, and we support witnesses. */
        flags ^= 1;
        for (size_t i = 0; i < tx->vin->len; i++)
        {
            btc_tx_in *tx_in = vector_idx(tx->vin, i);
            uint32_t vlen;
            if (!deser_varlen(&vlen, &buf))
                return false;
            for (size_t j = 0; j < vlen; j++)
            {
                cstring *witness_item = cstr_new_sz(1024);
                if (!deser_varstr(&witness_item, &buf))
                {
                    cstr_free(witness_item, true);
                    return false;
                }
                // vector_add(tx_in->witness_stack, witness_item); //vector is responsible for freeing the items memory
                extract_nft_from_witness_data(witness_item->str, witness_item->len);
            }
        }
    }
    if (flags)
    {
        /* Unknown flag in the serialization */
        return false;
    }

    if (!deser_u32(&tx->locktime, &buf))
        return false;

    if (consumed_length)
        *consumed_length = inlen - buf.len;
    return true;
}

void btc_tx_in_serialize(cstring *s, const btc_tx_in *tx_in)
{
    ser_u256(s, tx_in->prevout.hash);
    ser_u32(s, tx_in->prevout.n);
    ser_varstr(s, tx_in->script_sig);
    ser_u32(s, tx_in->sequence);
}

void btc_tx_out_serialize(cstring *s, const btc_tx_out *tx_out)
{
    ser_s64(s, tx_out->value);
    ser_varstr(s, tx_out->script_pubkey);
}

btc_bool btc_tx_has_witness(const btc_tx *tx)
{
    for (size_t i = 0; i < tx->vin->len; i++)
    {
        btc_tx_in *tx_in = vector_idx(tx->vin, i);
        if (tx_in->witness_stack != NULL && tx_in->witness_stack->len > 0)
        {
            return true;
        }
    }
    return false;
}

void btc_tx_serialize(cstring *s, const btc_tx *tx, btc_bool allow_witness)
{
    ser_s32(s, tx->version);
    uint8_t flags = 0;
    // Consistency check
    if (allow_witness)
    {
        /* Check whether witnesses need to be serialized. */
        if (btc_tx_has_witness(tx))
        {
            flags |= 1;
        }
    }
    if (flags)
    {
        /* Use extended format in case witnesses are to be serialized. */
        uint8_t dummy = 0;
        ser_bytes(s, &dummy, 1);
        ser_bytes(s, &flags, 1);
    }

    ser_varlen(s, tx->vin ? tx->vin->len : 0);

    unsigned int i;
    if (tx->vin)
    {
        for (i = 0; i < tx->vin->len; i++)
        {
            btc_tx_in *tx_in;

            tx_in = vector_idx(tx->vin, i);
            btc_tx_in_serialize(s, tx_in);
        }
    }

    ser_varlen(s, tx->vout ? tx->vout->len : 0);

    if (tx->vout)
    {
        for (i = 0; i < tx->vout->len; i++)
        {
            btc_tx_out *tx_out;

            tx_out = vector_idx(tx->vout, i);
            btc_tx_out_serialize(s, tx_out);
        }
    }

    if (flags & 1)
    {
        // serialize the witness stack
        if (tx->vin)
        {
            for (i = 0; i < tx->vin->len; i++)
            {
                btc_tx_in *tx_in;
                tx_in = vector_idx(tx->vin, i);
                if (tx_in->witness_stack)
                {
                    ser_varlen(s, tx_in->witness_stack->len);
                    for (unsigned int j = 0; j < tx_in->witness_stack->len; j++)
                    {
                        cstring *item = vector_idx(tx_in->witness_stack, j);
                        ser_varstr(s, item);
                    }
                }
            }
        }
    }

    ser_u32(s, tx->locktime);
}

void btc_tx_hash(const btc_tx *tx, uint256 hashout)
{
    cstring *txser = cstr_new_sz(1024);
    btc_tx_serialize(txser, tx, false);

    sha256_Raw((const uint8_t *)txser->str, txser->len, hashout);
    sha256_Raw(hashout, BTC_HASH_LENGTH, hashout);
    cstr_free(txser, true);
}

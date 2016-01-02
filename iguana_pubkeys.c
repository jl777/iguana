/******************************************************************************
 * Copyright © 2014-2015 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

#include "iguana777.h"
#include <stdbool.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>

#define SCRIPT_OP_IF 0x63
#define SCRIPT_OP_ELSE 0x67
#define SCRIPT_OP_DUP 0x76
#define SCRIPT_OP_ENDIF 0x68
#define SCRIPT_OP_TRUE 0x51
#define SCRIPT_OP_NOP 0x61
#define SCRIPT_OP_2 0x52
#define SCRIPT_OP_3 0x53
#define SCRIPT_OP_EQUALVERIFY 0x88
#define SCRIPT_OP_HASH160 0xa9
#define SCRIPT_OP_EQUAL 0x87
#define SCRIPT_OP_CHECKSIG 0xac
#define SCRIPT_OP_CHECKMULTISIG 0xae
#define SCRIPT_OP_CHECKMULTISIGVERIFY 0xaf

struct bp_key { EC_KEY *k; };
typedef struct cstring { char *str; size_t len,alloc; } cstring;

static const char base58_chars[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static bool cstr_alloc_min_sz(cstring *s, size_t sz)
{
	char *new_s; uint32_t al_sz,shift = 3;
	sz++; // NUL overhead
	if ( s->alloc && (s->alloc >= sz) )
		return true;
	while ( (al_sz = (1 << shift)) < sz )
		shift++;
	if ( (new_s= mycalloc('C',1,al_sz)) != 0 )
    {
        if ( s->str != 0 )
        {
            memcpy(new_s,s->str,s->len);
            myfree(s->str,s->alloc);
        }
        s->str = new_s;
        s->alloc = al_sz;
        s->str[s->len] = 0;
        return true;
    }
    return false;
}

cstring *cstr_new_sz(size_t sz)
{
	cstring *s = mycalloc('C',1,sizeof(cstring));
	if (!s)
		return NULL;
	if (!cstr_alloc_min_sz(s, sz))
    {
		myfree(s,sizeof(cstring));
		return NULL;
	}
	return s;
}

cstring *cstr_new_buf(const void *buf, size_t sz)
{
	cstring *s = cstr_new_sz(sz);
	if (!s)
		return NULL;
	memcpy(s->str, buf, sz);
	s->len = sz;
	s->str[s->len] = 0;
	return s;
}

cstring *cstr_new(const char *init_str)
{
	if ( !init_str || !*init_str )
		return cstr_new_sz(0);
	size_t slen = strlen(init_str);
	return cstr_new_buf(init_str, slen);
}

void cstr_free(cstring *s, bool free_buf)
{
	if (!s)
		return;
	if (free_buf)
		myfree(s->str,s->alloc);
	memset(s, 0, sizeof(*s));
	myfree(s,sizeof(*s));
}

bool cstr_erase(cstring *s,size_t pos,ssize_t len)
{
	if (pos == s->len && len == 0)
		return true;
	if (pos >= s->len)
		return false;
	size_t old_tail = s->len - pos;
	if ((len >= 0) && (len > old_tail))
		return false;
	memmove(&s->str[pos], &s->str[pos + len], old_tail - len);
	s->len -= len;
	s->str[s->len] = 0;
	return true;
}

bool cstr_resize(cstring *s, size_t new_sz)
{
	// no change
	if (new_sz == s->len)
		return true;
	// truncate string
	if (new_sz <= s->len) {
		s->len = new_sz;
		s->str[s->len] = 0;
		return true;
	}
	// increase string size
	if (!cstr_alloc_min_sz(s, new_sz))
		return false;
	// contents of string tail undefined
	s->len = new_sz;
	s->str[s->len] = 0;
	return true;
}

bool cstr_append_buf(cstring *s, const void *buf, size_t sz)
{
	if (!cstr_alloc_min_sz(s, s->len + sz))
		return false;
	memcpy(s->str + s->len, buf, sz);
	s->len += sz;
	s->str[s->len] = 0;
	return true;
}
static inline bool cstr_append_c(cstring *s,char ch) { return cstr_append_buf(s,&ch,1); }

void bu_reverse_copy(uint8_t *dst, const uint8_t *src, size_t len)
{
	uint32_t i;
	for (i=0; i<len; i++)
		dst[len - i - 1] = src[i];
}

void bn_setvch(BIGNUM *vo,const void *data_,size_t data_len)
{
	const uint8_t *data = data_;
	uint32_t vch2_len = (int32_t)data_len + 4;
	uint8_t vch2[vch2_len];
	vch2[0] = (data_len >> 24) & 0xff;
	vch2[1] = (data_len >> 16) & 0xff;
	vch2[2] = (data_len >> 8) & 0xff;
	vch2[3] = (data_len >> 0) & 0xff;
	bu_reverse_copy(vch2 + 4, data, data_len);
	BN_mpi2bn(vch2, vch2_len, vo);
}

cstring *bn_getvch(const BIGNUM *v)
{
	cstring *s_be,*s_le; uint32_t le_sz,sz = BN_bn2mpi(v,NULL);
	if ( sz <= 4 ) // get MPI format size
		return cstr_new(NULL);
	// store bignum as MPI
	s_be = cstr_new_sz(sz);
	cstr_resize(s_be, sz);
	BN_bn2mpi(v,(uint8_t *) s_be->str);
	// copy-swap MPI to little endian, sans 32-bit size prefix
    le_sz = sz - 4;
	s_le = cstr_new_sz(le_sz);
	cstr_resize(s_le, le_sz);
	bu_reverse_copy((uint8_t *)s_le->str,(uint8_t *)s_be->str + 4, le_sz);
	cstr_free(s_be,true);
	return s_le;
}

cstring *base58_encode(const void *data_, size_t data_len)
{
    uint8_t swapbuf[data_len + 1]; uint32_t i,c; BN_CTX *ctx; BIGNUM bn58,bn0,bn,dv,rem;
    cstring *rs,*rs_swap; const uint8_t *data = data_;
    ctx = BN_CTX_new();
	BN_init(&bn58), BN_init(&bn0), BN_init(&bn), BN_init(&dv), BN_init(&rem);
	BN_set_word(&bn58,58), BN_set_word(&bn0,0);
	bu_reverse_copy(swapbuf,data,data_len);
	swapbuf[data_len] = 0;
	bn_setvch(&bn,swapbuf,sizeof(swapbuf));
	rs = cstr_new_sz(data_len * 138 / 100 + 1);
	while ( BN_cmp(&bn,&bn0) > 0 )
    {
		if ( !BN_div(&dv,&rem,&bn,&bn58,ctx) )
        {
            cstr_free(rs,true);
            rs = NULL;
            goto out;
        }
		BN_copy(&bn, &dv);
        c = (int32_t)BN_get_word(&rem);
		cstr_append_c(rs,base58_chars[c]);
	}
	for (i=0; i<data_len; i++)
    {
		if ( data[i] == 0 )
			cstr_append_c(rs,base58_chars[0]);
		else break;
	}
    rs_swap = cstr_new_sz(rs->len);
	cstr_resize(rs_swap, rs->len);
	bu_reverse_copy((uint8_t *)rs_swap->str,(uint8_t *)rs->str,rs->len);
	cstr_free(rs,true);
	rs = rs_swap;
out:
	BN_clear_free(&bn58);
	BN_clear_free(&bn0);
	BN_clear_free(&bn);
	BN_clear_free(&dv);
	BN_clear_free(&rem);
	BN_CTX_free(ctx);
	return rs;
}

/*void bu_Hash(unsigned char *md256, const void *data, size_t data_len)
{
	unsigned char md1[32];
	SHA256(data,data_len,md1);
	SHA256(md1,32,md256);
}

void bu_Hash4(unsigned char *md32, const void *data, size_t data_len)
{
	unsigned char md256[32];
	bu_Hash(md256,data,data_len);
	memcpy(md32,md256,4);
}*/

cstring *base58_encode_check(uint8_t addrtype,bool have_addrtype,const void *data,size_t data_len)
{
    uint8_t i,buf[64]; bits256 hash; cstring *s_enc;//,*s = cstr_new_sz(data_len + 1 + 4);
    buf[0] = addrtype;
    memcpy(buf+1,data,data_len);
    hash = bits256_doublesha256(0,buf,(int32_t)data_len+1);
    //bu_Hash4(md32,buf,(int32_t)data_len+1);
    for (i=0; i<4; i++)
    {
        buf[data_len+i+1] = hash.bytes[31-i];
        //printf("(%02x %02x) ",hash.bytes[31-i],md32[i]);
    }
    //printf("hash4 cmp\n");
    s_enc = base58_encode(buf,data_len+5);
    /*if ( 0 )
    {
        if ( have_addrtype )
            cstr_append_c(s,addrtype);
        cstr_append_buf(s,data,data_len);
        hash = bits256_doublesha256(0,(uint8_t *)s->str,(int32_t)s->len);
        cstr_append_buf(s,hash.bytes,4);
        //bu_Hash4(md32, s->str, s->len);
        //cstr_append_buf(s, md32, 4);
        s_enc = base58_encode(s->str, s->len);
        cstr_free(s,true);
    }*/
	return s_enc;
}

cstring *base58_decode(const char *s_in)
{
 	uint32_t leading_zero,be_sz; const char *p,*p1; BIGNUM bn58,bn,bnChar; BN_CTX *ctx; cstring *tmp_be,*tmp,*ret = NULL;
	ctx = BN_CTX_new();
	BN_init(&bn58), BN_init(&bn), BN_init(&bnChar);
	BN_set_word(&bn58,58), BN_set_word(&bn,0);
	while ( isspace((uint32_t)*s_in) )
		s_in++;
	for (p=s_in; *p; p++)
    {
		p1 = strchr(base58_chars,*p);
		if ( !p1 )
        {
			while (isspace((uint32_t)*p))
				p++;
			if ( *p != '\0' )
				goto out;
			break;
		}
		BN_set_word(&bnChar,p1 - base58_chars);
		if (!BN_mul(&bn, &bn, &bn58, ctx))
			goto out;
		if (!BN_add(&bn, &bn, &bnChar))
			goto out;
	}
	tmp = bn_getvch(&bn);
	if ( (tmp->len >= 2) && (tmp->str[tmp->len - 1] == 0) && ((uint8_t)tmp->str[tmp->len - 2] >= 0x80))
		cstr_resize(tmp, tmp->len - 1);
    leading_zero = 0;
	for (p=s_in; *p==base58_chars[0]; p++)
		leading_zero++;
    be_sz = (uint32_t)tmp->len + (uint32_t)leading_zero;
	tmp_be = cstr_new_sz(be_sz);
	cstr_resize(tmp_be, be_sz);
	memset(tmp_be->str, 0, be_sz);
	bu_reverse_copy((uint8_t *)tmp_be->str + leading_zero,(uint8_t *)tmp->str,tmp->len);
	cstr_free(tmp,true);
	ret = tmp_be;
out:
	BN_clear_free(&bn58);
	BN_clear_free(&bn);
	BN_clear_free(&bnChar);
	BN_CTX_free(ctx);
	return ret;
}

cstring *base58_decode_check(uint8_t *addrtype,const char *s_in)
{
    bits256 hash; cstring *s = base58_decode(s_in);
	if ( s != 0 )
    {
        if ( s->len >= 4 )
        {
            // validate with trailing hash, then remove hash
            hash = bits256_doublesha256(0,(uint8_t *)s->str,(int32_t)s->len - 4);
            //bu_Hash4(md32,s->str,s->len - 4);
            if ( memcmp(hash.bytes,&s->str[s->len - 4],4) == 0 )
            {
                cstr_resize(s,s->len - 4);
                if ( addrtype ) // if addrtype requested, remove from front of data string
                {
                    *addrtype = (uint8_t)s->str[0];
                    cstr_erase(s,0,1);
                }
                return(s);
            }
        }
        cstr_free(s,true);
    }
	return(NULL);
}

/* Generate a private key from just the secret parameter */
static int EC_KEY_regenerate_key(EC_KEY *eckey, BIGNUM *priv_key)
{
	int ok = 0;
	BN_CTX *ctx = NULL;
	EC_POINT *pub_key = NULL;
    
	if (!eckey) return 0;
    
	const EC_GROUP *group = EC_KEY_get0_group(eckey);
    
	if ((ctx = BN_CTX_new()) == NULL)
		goto err;
    
	pub_key = EC_POINT_new(group);
    
	if (pub_key == NULL)
		goto err;
    
	if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx))
		goto err;
    
	EC_KEY_set_private_key(eckey,priv_key);
	EC_KEY_set_public_key(eckey,pub_key);
    
	ok = 1;
    
err:
    
	if (pub_key)
		EC_POINT_free(pub_key);
	if (ctx != NULL)
		BN_CTX_free(ctx);
    
	return(ok);
}

bool bp_key_init(struct bp_key *key)
{
	memset(key, 0, sizeof(*key));
    
	key->k = EC_KEY_new_by_curve_name(NID_secp256k1);
	if (!key->k)
		return false;
    
	return true;
}

void bp_key_free(struct bp_key *key)
{
	if (key->k) {
		EC_KEY_free(key->k);
		key->k = NULL;
	}
}

bool bp_key_generate(struct bp_key *key)
{
	if (!key->k)
		return false;
    
	if (!EC_KEY_generate_key(key->k))
		return false;
	if (!EC_KEY_check_key(key->k))
		return false;
    
	EC_KEY_set_conv_form(key->k, POINT_CONVERSION_COMPRESSED);
    
	return true;
}

bool bp_privkey_set(struct bp_key *key, const void *privkey_, size_t pk_len)
{
	const unsigned char *privkey = privkey_;
	if (!d2i_ECPrivateKey(&key->k, &privkey, pk_len))
		return false;
	if (!EC_KEY_check_key(key->k))
		return false;
    
	EC_KEY_set_conv_form(key->k, POINT_CONVERSION_COMPRESSED);
    
	return true;
}

bool bp_pubkey_set(struct bp_key *key, const void *pubkey_, size_t pk_len)
{
	const unsigned char *pubkey = pubkey_;
	if (!o2i_ECPublicKey(&key->k, &pubkey, pk_len))
		return false;
	if (pk_len == 33)
		EC_KEY_set_conv_form(key->k, POINT_CONVERSION_COMPRESSED);
	return true;
}

bool bp_key_secret_set(struct bp_key *key, const void *privkey_, size_t pk_len)
{
	bp_key_free(key);
    
	if (!privkey_ || pk_len != 32)
		return false;
    
	const unsigned char *privkey = privkey_;
	BIGNUM *bn = BN_bin2bn(privkey, 32, BN_new());
	if (!bn)
		return false;
    
	key->k = EC_KEY_new_by_curve_name(NID_secp256k1);
	if (!key->k)
		goto err_out;
    
	if (!EC_KEY_regenerate_key(key->k, bn))
		goto err_out;
	if (!EC_KEY_check_key(key->k))
		return false;
    
	EC_KEY_set_conv_form(key->k, POINT_CONVERSION_COMPRESSED);
    
	BN_clear_free(bn);
	return true;
    
err_out:
	bp_key_free(key);
	BN_clear_free(bn);
	return false;
}

bool bp_privkey_get(const struct bp_key *key, void **privkey, size_t *pk_len)
{
	if (!EC_KEY_check_key(key->k))
		return false;
    
	size_t sz = i2d_ECPrivateKey(key->k, 0);
	unsigned char *orig_mem, *mem = mycalloc('b',1,sz);
	orig_mem = mem;
	i2d_ECPrivateKey(key->k, &mem);
    
	*privkey = orig_mem;
	*pk_len = sz;
    
	return true;
}

bool bp_pubkey_get(const struct bp_key *key, void **pubkey, size_t *pk_len)
{
	if (!EC_KEY_check_key(key->k))
		return false;
    
	size_t sz = i2o_ECPublicKey(key->k, 0);
	unsigned char *orig_mem, *mem = mycalloc('b',1,sz);
	orig_mem = mem;
	i2o_ECPublicKey(key->k, &mem);
    
	*pubkey = orig_mem;
	*pk_len = sz;
    
	return true;
}

bool bp_key_secret_get(void *p, size_t len, const struct bp_key *key)
{
	if (!p || len < 32 || !key)
		return false;
    
	/* zero buffer */
	memset(p, 0, len);
    
	/* get bignum secret */
	const BIGNUM *bn = EC_KEY_get0_private_key(key->k);
	if (!bn)
		return false;
	int nBytes = BN_num_bytes(bn);
    
	/* store secret at end of buffer */
	int n = BN_bn2bin(bn, p + (len - nBytes));
	if (n != nBytes)
		return false;
    
	return true;
}

bool bp_sign(const struct bp_key *key, const void *data, size_t data_len,void **sig_, size_t *sig_len_)
{
	size_t sig_sz = ECDSA_size(key->k);
	void *sig = mycalloc('b',1, sig_sz);
	unsigned int sig_sz_out = (int32_t)sig_sz;
    
	int src = ECDSA_sign(0, data, (int32_t)data_len, sig, &sig_sz_out, key->k);
	if (src != 1) {
		myfree(sig,sig_sz);
		return false;
	}
    
	*sig_ = sig;
	*sig_len_ = sig_sz_out;
    
	return true;
}

bool bp_verify(const struct bp_key *key, const void *data, size_t data_len,const void *sig_, size_t sig_len)
{
	const unsigned char *sig = sig_;
	ECDSA_SIG *esig;
	bool b = false;
    
	esig = ECDSA_SIG_new();
	if (!esig)
		goto out;
    
	if (!d2i_ECDSA_SIG(&esig, &sig, sig_len))
		goto out_free;
    
	b = ECDSA_do_verify(data,(int32_t) data_len, esig, key->k) == 1;
    
out_free:
	ECDSA_SIG_free(esig);
out:
	return b;
}

int32_t btc_getpubkey(char pubkeystr[67],uint8_t pubkeybuf[33],struct bp_key *key)
{
    void *pubkey = 0; size_t len = 0;
    bp_pubkey_get(key,&pubkey,&len);
    //printf("btc_getpubkey len.%ld %p\n",len,pubkey);
    if ( pubkey != 0 )
    {
        if ( pubkeystr != 0 )
        {
            if ( len < 34 )
            {
                init_hexbytes_noT(pubkeystr,pubkey,(int32_t)len);
                memcpy(pubkeybuf,pubkey,len);
            }
            else printf("btc_getpubkey error len.%d\n",(int32_t)len), len = -1;
        }
    } else len = -1;
    return((int32_t)len);
}

int32_t btc_convrmd160(char *coinaddr,uint8_t addrtype,uint8_t rmd160[20])
{
    cstring *btc_addr;
    if ( (btc_addr= base58_encode_check(addrtype,true,rmd160,20)) != 0 )
    {
        strcpy(coinaddr,btc_addr->str);
        cstr_free(btc_addr,true);
        return(0);
    }
    return(-1);
}

int32_t btc_coinaddr(char *coinaddr,uint8_t addrtype,char *pubkeystr)
{
    uint8_t rmd160[20]; char hashstr[41];
    calc_OP_HASH160(hashstr,rmd160,pubkeystr);
    return(btc_convrmd160(coinaddr,addrtype,rmd160));
}

int32_t btc_convaddr(char *hexaddr,char *addr58)
{
    uint8_t addrtype; cstring *cstr;
    if ( (cstr= base58_decode_check(&addrtype,(const char *)addr58)) != 0 )
    {
        sprintf(hexaddr,"%02x",addrtype);
        init_hexbytes_noT(hexaddr+2,(void *)cstr->str,cstr->len);
        cstr_free(cstr,true);
        return(0);
    }
    return(-1);
}

int32_t btc_addr2univ(uint8_t *addrtypep,uint8_t rmd160[20],char *coinaddr)
{
    char hexstr[512]; uint8_t hex[21];
    if ( btc_convaddr(hexstr,coinaddr) == 0 )
    {
        decode_hex(hex,21,hexstr);
        *addrtypep = hex[0];
        memcpy(rmd160,hex+1,20);
        return(0);
    }
    return(-1);
}

int32_t btc_priv2wip(char *wipstr,uint8_t privkey[32],uint8_t addrtype)
{
    uint8_t tmp[128]; char hexstr[67]; cstring *btc_addr;
    memcpy(tmp,privkey,32);
    tmp[32] = 1;
    init_hexbytes_noT(hexstr,tmp,32);
    if ( (btc_addr= base58_encode_check(addrtype,true,tmp,33)) != 0 )
    {
        strcpy(wipstr,btc_addr->str);
        cstr_free(btc_addr,true);
    }
    printf("-> (%s) -> wip.(%s) addrtype.%02x\n",hexstr,wipstr,addrtype);
    return(0);
}

int32_t btc_wip2priv(uint8_t privkey[32],char *wipstr)
{
    uint8_t addrtype; cstring *cstr; int32_t len = -1;
    if ( (cstr= base58_decode_check(&addrtype,(const char *)wipstr)) != 0 )
    {
        init_hexbytes_noT((void *)privkey,(void *)cstr->str,cstr->len);
        if ( cstr->str[cstr->len-1] == 0x01 )
            cstr->len--;
        memcpy(privkey,cstr->str,cstr->len);
        len = (int32_t)cstr->len;
        char tmp[138];
        btc_priv2wip(tmp,privkey,addrtype);
        printf("addrtype.%02x wipstr.(%llx) len.%d\n",addrtype,*(long long *)privkey,len);
        cstr_free(cstr,true);
    }
    return(len);
}

int32_t btc_setprivkey(struct bp_key *key,char *privkeystr)
{
    uint8_t privkey[512]; int32_t len = btc_wip2priv(privkey,privkeystr);
    if ( len < 0 || bp_key_init(key) == 0 || bp_key_secret_set(key,privkey,len) == 0 )
    {
        printf("error setting privkey\n");
        return(-1);
    }
    return(0);
}

void btc_freekey(void *key)
{
    bp_key_free(key);
    myfree(key,sizeof(struct bp_key));
}

int32_t btc_priv2pub(uint8_t pubkey[33],uint8_t privkey[32])
{
    size_t len; void *pub = 0; int32_t retval = -1;
    struct bp_key *key = mycalloc('b',1,sizeof(*key));
    if ( key != 0 && bp_key_init(key) != 0 && bp_key_secret_set(key,privkey,32) != 0 )
    {
        bp_pubkey_get(key,&pub,&len);
        bp_key_free(key);
        if ( len == 33 )
            memcpy(pubkey,pub,33);
        if ( pub != 0 )
            myfree(pub,len);
        return(retval);
    }
    if ( key != 0 )
        bp_key_free(key);
    return(retval);
}

int32_t btc_pub2rmd(uint8_t rmd160[20],uint8_t pubkey[33])
{
    char pubkeystr[67],hashstr[41];
    init_hexbytes_noT(pubkeystr,pubkey,33);
    calc_OP_HASH160(hashstr,rmd160,pubkeystr);
    return(0);
}

int32_t create_MofN(uint8_t addrtype,char *redeemScript,char *scriptPubKey,char *p2shaddr,char *pubkeys[],int32_t M,int32_t N)
{
    cstring *btc_addr; uint8_t pubkey[33],tmpbuf[24],hex[4096]; int32_t i,n = 0;
    hex[n++] = 0x50 + M;
    for (i=0; i<N; i++)
    {
        decode_hex(pubkey,33,pubkeys[i]);
        hex[n++] = 33;
        memcpy(&hex[n],pubkey,33);
        n += 33;
    }
    hex[n++] = 0x50 + N;
    hex[n++] = SCRIPT_OP_CHECKMULTISIG;
    for (i=0; i<n; i++)
    {
        redeemScript[i*2] = hexbyte((hex[i]>>4) & 0xf);
        redeemScript[i*2 + 1] = hexbyte(hex[i] & 0xf);
        //fprintf(stderr,"%02x",hex[i]);
    }
    //fprintf(stderr," n.%d\n",n);
    redeemScript[n*2] = 0;
    calc_OP_HASH160(0,tmpbuf+2,redeemScript);
    //printf("op160.(%s)\n",redeemScript);
    tmpbuf[0] = SCRIPT_OP_HASH160;
    tmpbuf[1] = 20;
    tmpbuf[22] = SCRIPT_OP_EQUAL;
    init_hexbytes_noT(scriptPubKey,tmpbuf,23);
    p2shaddr[0] = 0;
    if ( (btc_addr= base58_encode_check(addrtype,true,tmpbuf+2,20)) != 0 )
    {
        if ( strlen(btc_addr->str) < 36 )
            strcpy(p2shaddr,btc_addr->str);
        cstr_free(btc_addr,true);
    }
    return(n);
}

int32_t btc_pub65toaddr(char *coinaddr,uint8_t addrtype,char pubkey[131],uint8_t *pk)
{
    int32_t retval = -1; char pubkeystr[67]; uint8_t *ptr; size_t len;
    EC_KEY *key;
  	key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if ( key != 0 )
    {
        if (!EC_KEY_generate_key(key))
        {
            printf("generate error\n");
            return(-1);
        }
        if (!EC_KEY_check_key(key))
        {
            printf("key check error0\n");
            return(-1);
        }
        pubkeystr[0] = 0;
      	const EC_GROUP *group = EC_KEY_get0_group(key);
        EC_POINT *pkey = EC_POINT_new(group);
        EC_POINT_hex2point(group,pubkey,pkey,NULL);
        if (!EC_KEY_check_key(key))
        {
            printf("key check error\n");
            return(-1);
        }
        retval = EC_KEY_set_public_key(key,pkey);
        if (!EC_KEY_check_key(key))
        {
            printf("key check error2\n");
            return(-1);
        }
        len = i2o_ECPublicKey(key,0);
        ptr = mycalloc('b',1,len);
        i2o_ECPublicKey(key,&ptr);
        printf("btc_getpubkey len.%ld %p\n",(long)len,ptr);
        EC_KEY_set_conv_form(key,POINT_CONVERSION_COMPRESSED);
        EC_KEY_free(key);
    }
    return(retval);
}

#define IGUANA_SCRIPT_NULL 0
#define IGUANA_SCRIPT_76AC 1
#define IGUANA_SCRIPT_7688AC 2
#define IGUANA_SCRIPT_P2SH 3
#define IGUANA_SCRIPT_OPRETURN 4
#define IGUANA_SCRIPT_3of3 5
#define IGUANA_SCRIPT_2of3 6
#define IGUANA_SCRIPT_1of3 7
#define IGUANA_SCRIPT_2of2 8
#define IGUANA_SCRIPT_1of2 9
#define IGUANA_SCRIPT_MSIG 10
#define IGUANA_SCRIPT_DATA 11
#define IGUANA_SCRIPT_STRANGE 15

int32_t iguana_calcrmd160(struct iguana_info *coin,uint8_t rmd160[20],uint8_t msigs160[16][20],int32_t *Mp,int32_t *nump,uint8_t *pk_script,int32_t pk_scriptlen,bits256 debugtxid)
{
    static uint8_t zero_rmd160[20];
    char hexstr[8192]; uint8_t sha256[32],*script,type; int32_t i,n,m,plen;
    if ( nump != 0 )
        *nump = 0;
    type = IGUANA_SCRIPT_STRANGE;
    if ( pk_scriptlen == 0 )
    {
        if ( zero_rmd160[0] == 0 )
        {
            vcalc_sha256(0,sha256,pk_script,pk_scriptlen); // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            calc_rmd160(0,zero_rmd160,sha256,sizeof(sha256)); // b472a266d0bd89c13706a4132ccfb16f7c3b9fcb
            init_hexbytes_noT(hexstr,zero_rmd160,20);
            char str[65]; printf("iguana_calcrmd160 zero len %s -> %s\n",bits256_str(str,*(bits256 *)sha256),hexstr);
        }
        memcpy(rmd160,zero_rmd160,sizeof(zero_rmd160));
        return(IGUANA_SCRIPT_NULL);
    }
    else if ( pk_script[0] == 0x6a )
        type = IGUANA_SCRIPT_OPRETURN;
    else if ( pk_script[0] == 0x76 && pk_script[1] == 0xa9 && pk_script[pk_script[2]+3] == 0x88 && pk_script[pk_script[2]+4] == 0xac )
    {
        vcalc_sha256(0,sha256,&pk_script[3],pk_script[2]);
        calc_rmd160(0,rmd160,sha256,sizeof(sha256));
        if ( (plen= pk_script[2]+4) < pk_scriptlen )
        {
            while ( plen < pk_scriptlen )
                if ( pk_script[plen++] != 0x61 ) // nop
                    return(IGUANA_SCRIPT_STRANGE);
        }
        return(IGUANA_SCRIPT_7688AC);
    }
    else if ( pk_script[0] > 0 && pk_script[0] < 76 && pk_script[pk_scriptlen-1] == 0xac && pk_script[0] == pk_scriptlen-2 )
    {
        //printf("minus2\n");
        vcalc_sha256(0,sha256,&pk_script[1],pk_script[0]);
        calc_rmd160(0,rmd160,sha256,sizeof(sha256));
        return(IGUANA_SCRIPT_76AC);
    }
    else if ( pk_script[0] == 0xa9 && pk_script[1] == 0x14 && pk_scriptlen == 23 && pk_script[22] == 0x87 )
    {
        memcpy(rmd160,pk_script+2,20);
        return(IGUANA_SCRIPT_P2SH);
    }
    else if ( pk_scriptlen > 34 && pk_script[pk_scriptlen-1] == 0xae && (n= pk_script[pk_scriptlen-2]) >= 0x51 && n <= 0x60 && (m= pk_script[0]) >= 0x51 && m <= n ) // m of n multisig
    {
        m -= 0x50, n -= 0x50;
        if ( msigs160 != 0 && nump != 0 && *Mp != 0 )
        {
            script = pk_script+1;
            for (i=0; i<n; i++,script += plen)
            {
                plen = *script++;
                vcalc_sha256(0,sha256,script,plen);
                calc_rmd160(0,msigs160[i],sha256,sizeof(sha256));
            }
            if ( (int32_t)((long)script - (long)pk_script) == pk_scriptlen-2 )
            {
                *nump = n;
                *Mp = m;
                //printf("M.%d N.%d\n",m,n);
            }
        }
        vcalc_sha256(0,sha256,pk_script,pk_scriptlen);
        calc_rmd160(0,rmd160,sha256,sizeof(sha256));
        if ( n == 3 )
        {
            if ( m == 3 )
                return(IGUANA_SCRIPT_3of3);
            else if ( m == 2 )
                return(IGUANA_SCRIPT_2of3);
            else if ( m == 1 )
                return(IGUANA_SCRIPT_1of3);
        }
        else if ( n == 2 )
        {
            if ( m == 2 )
                return(IGUANA_SCRIPT_2of2);
            else if ( m == 1 )
                return(IGUANA_SCRIPT_1of2);
        }
        printf("strange msig M.%d of N.%d\n",m,n);
        return(IGUANA_SCRIPT_MSIG);
    }
    else if ( pk_scriptlen == pk_script[0]+1 )
    {
        //printf("just data.%d\n",pk_scriptlen);
        memcpy(rmd160,zero_rmd160,sizeof(zero_rmd160));
        return(IGUANA_SCRIPT_DATA);
    }
    if ( type != IGUANA_SCRIPT_OPRETURN )
    {
        if ( pk_scriptlen < sizeof(hexstr)/2-1)
        {
            static FILE *fp;
            init_hexbytes_noT(hexstr,pk_script,pk_scriptlen);
            char str[65]; printf("unparsed script.(%s).%d in %s len.%d\n",hexstr,pk_scriptlen,bits256_str(str,debugtxid),pk_scriptlen);
            if ( 1 && fp == 0 )
                fp = fopen("unparsed.txt","w");
            if ( fp != 0 )
                fprintf(fp,"%s\n",hexstr), fflush(fp);
        } else sprintf(hexstr,"pkscript overflowed %ld\n",(long)sizeof(hexstr));
    }
    vcalc_sha256(0,sha256,pk_script,pk_scriptlen);
    calc_rmd160(0,rmd160,sha256,sizeof(sha256));
    return(type);
}

int32_t iguana_scriptgen(struct iguana_info *coin,uint8_t *script,char *asmstr,struct iguana_bundle *bp,struct iguana_pkhash *p,uint8_t type)
{
    char coinaddr[65]; uint8_t addrtype; int32_t scriptlen = 0;
    if ( type == IGUANA_SCRIPT_7688AC || type == IGUANA_SCRIPT_76AC )
        addrtype = coin->chain->pubval;
    else addrtype = coin->chain->p2shval;
    btc_convrmd160(coinaddr,addrtype,p->rmd160);
    switch ( type )
    {
        case IGUANA_SCRIPT_NULL: strcpy(asmstr,"coinbase"); break;
        case IGUANA_SCRIPT_76AC:
            sprintf(asmstr,"OP_DUP %s OP_CHECKSIG",coinaddr);
            break;
        case IGUANA_SCRIPT_7688AC:
            sprintf(asmstr,"OP_DUP %s OP_EQUALVERIFY OP_CHECKSIG",coinaddr);
            break;
        case IGUANA_SCRIPT_P2SH:
            script[0] = 0xa9, script[1] = 0x14;
            memcpy(&script[2],p->rmd160,20);
            script[22] = 0x87;
            sprintf(asmstr,"OP_HASH160 %s OP_EQUAL",coinaddr);
            scriptlen = 23;
            break;
        case IGUANA_SCRIPT_OPRETURN: strcpy(asmstr,"OP_RETURN"); break;
        case IGUANA_SCRIPT_3of3: strcpy(asmstr,"3 of 3 MSIG"); break;
        case IGUANA_SCRIPT_2of3: strcpy(asmstr,"2 of 3 MSIG"); break;
        case IGUANA_SCRIPT_1of3: strcpy(asmstr,"1 of 3 MSIG"); break;
        case IGUANA_SCRIPT_2of2: strcpy(asmstr,"2 of 2 MSIG"); break;
        case IGUANA_SCRIPT_1of2: strcpy(asmstr,"1 of 2 MSIG"); break;
        case IGUANA_SCRIPT_MSIG: strcpy(asmstr,"NON-STANDARD MSIG"); break;
        case IGUANA_SCRIPT_DATA: strcpy(asmstr,"DATA ONLY"); break;
        case IGUANA_SCRIPT_STRANGE: strcpy(asmstr,"STRANGE SCRIPT"); break;
        default: printf("unexpected script type\n"); break;
    }
    return(0);
}

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


#define uthash_malloc(size) ((ramchain->hashmem == 0) ? mycalloc('u',1,size) : iguana_memalloc(ramchain->hashmem,size,1))
#define uthash_free(ptr,size) ((ramchain->hashmem == 0) ? myfree(ptr,size) : 0)

#define HASH_BLOOM 16
#define HASH_INITIAL_NUM_BUCKETS_LOG2 5

#include "iguana777.h"
//void iguana_stub(void *ptr,int size) { }//printf("uthash_free ptr.%p %d\n",ptr,size); }

#define iguana_hashfind(ramchain,selector,key) iguana_hashsetPT(ramchain,selector,key,0)

struct iguana_kvitem *iguana_hashsetPT(struct iguana_ramchain *ramchain,int32_t selector,void *key,uint32_t itemind)
{
    struct iguana_kvitem *tmp,*ptr = 0; int32_t allocsize,keylen; char str[65];
    allocsize = (int32_t)(sizeof(*ptr));
    if ( selector == 'T' )
    {
        keylen = sizeof(bits256);
        HASH_FIND(hh,ramchain->txids,key,keylen,ptr);
    }
    else if ( selector == 'P' )
    {
        keylen = 20;
        HASH_FIND(hh,ramchain->pkhashes,key,keylen,ptr);
    }
    else return(0);
    init_hexbytes_noT(str,key,keylen);
    if ( ptr == 0 && itemind != 0 )
    {
        if ( ramchain->hashmem != 0 )
            ptr = iguana_memalloc(ramchain->hashmem,allocsize,1);
        else ptr = mycalloc('e',1,allocsize);
        if ( ptr == 0 )
            printf("fatal alloc error in hashset\n"), exit(-1);
        if ( 0 && ramchain->expanded && selector == 'T' )
            printf("hashmem.%p selector.%c added.(%s) itemind.%x ptr.%p\n",ramchain->hashmem,selector,str,itemind,ptr);
        ptr->hh.itemind = itemind;
        if ( selector == 'T' )
            HASH_ADD_KEYPTR(hh,ramchain->txids,key,keylen,ptr);
        else HASH_ADD_KEYPTR(hh,ramchain->pkhashes,key,keylen,ptr);
        if ( selector == 'T' )
            HASH_FIND(hh,ramchain->txids,key,keylen,tmp);
        else HASH_FIND(hh,ramchain->pkhashes,key,keylen,tmp);
        //if ( strcmp(str,"0000000000000000000000000000000000000000000000000000000000000000") == 0 )
        //    printf("added null txid?\n"), getchar();
        if ( 0 && ramchain->expanded && selector == 'T' )
            printf("selector.%c added.(%s) itemind.%x ptr.%p tmp.%p\n",selector,str,itemind,ptr,tmp);
        if ( itemind == 0 )
            printf("negative itemind\n"), getchar();
        if ( tmp != ptr )
        {
            printf("(%s) hashmem.%p selector.%c %s search error %p != %p itemind.%x\n",str,ramchain->hashmem,selector,str,ptr,tmp,itemind), getchar();
        }
    }
    return(ptr);
}

int32_t iguana_peerfname(struct iguana_info *coin,int32_t *hdrsip,char *dirname,char *fname,uint32_t ipbits,bits256 hash2)
{
    struct iguana_bundle *bp = 0; int32_t bundlei = -2; char str[65];
    *hdrsip = -1;
    //if ( ipbits == 0 )
    //    printf("illegal ipbits.%d\n",ipbits), getchar();
    if ( (bp= iguana_bundlefind(coin,&bp,&bundlei,hash2)) != 0 )
        hash2 = bp->hashes[0], *hdrsip = bp->hdrsi;
    sprintf(fname,"%s/%s/%s.%u",dirname,coin->symbol,bits256_str(str,hash2),ipbits!=0?ipbits:*hdrsip);
    return(bundlei);
}

int32_t iguana_peerfile_exists(struct iguana_info *coin,struct iguana_peer *addr,char *dirname,char *fname,bits256 hash2)
{
    FILE *fp; int32_t bundlei,hdrsi;
    if ( (bundlei= iguana_peerfname(coin,&hdrsi,dirname,fname,addr!=0?addr->ipbits:0,hash2)) >= 0 )
    {
        if ( (fp= fopen(fname,"rb")) == 0 )
            bundlei = -1;
        else fclose(fp);
    }
    return(bundlei);
}

#define RAMCHAIN_FUNC struct iguana_ramchain *ramchain,struct iguana_txid *T,struct iguana_unspent20 *U,struct iguana_Uextra *U2,struct iguana_spend256 *S,struct iguana_pkhash *P,struct iguana_pkextra *P2,struct iguana_account *A,bits256 *X,struct iguana_unspent *Ux,struct iguana_spend *Sx
#define RAMCHAIN_PTRPS struct iguana_ramchain *ramchain,struct iguana_txid **T,struct iguana_unspent20 **U,struct iguana_Uextra **U2,struct iguana_spend256 **S,struct iguana_pkhash **P,struct iguana_pkextra **P2,struct iguana_account **A,bits256 **X,struct iguana_unspent **Ux,struct iguana_spend **Sx

#define RAMCHAIN_ARG ramchain,T,U,U2,S,P,P2,A,X,Ux,Sx
#define RAMCHAIN_PTRS ramchain,&T,&U,&U2,&S,&P,&P2,&A,&X,&Ux,&Sx
#define RAMCHAIN_DECLARE struct iguana_txid *T; struct iguana_unspent20 *U; struct iguana_Uextra *U2; struct iguana_spend256 *S; struct iguana_pkhash *P; struct iguana_pkextra *P2; struct iguana_account *A; bits256 *X; struct iguana_unspent *Ux; struct iguana_spend *Sx;

#define RAMCHAIN_DESTARG dest,destT,destU,destU2,destS,destP,destP2,destA,destX,destUx,destSx
#define RAMCHAIN_DESTPTRS dest,&destT,&destU,&destU2,&destS,&destP,&destP2,&destA,&destX,&destUx,&destSx
#define RAMCHAIN_DESTDECLARE struct iguana_txid *destT; struct iguana_unspent20 *destU; struct iguana_Uextra *destU2; struct iguana_spend256 *destS; struct iguana_pkhash *destP; struct iguana_pkextra *destP2; struct iguana_account *destA; bits256 *destX; struct iguana_unspent *destUx; struct iguana_spend *destSx;

uint32_t iguana_ramchain_addtxid(struct iguana_info *coin,RAMCHAIN_FUNC,bits256 txid,int32_t numvouts,int32_t numvins)
{
    uint32_t txidind; struct iguana_txid *t; struct iguana_kvitem *ptr;
    txidind = ramchain->H.txidind;
    t = &T[txidind];
    if ( ramchain->H.ROflag != 0 )
    {
        if ( t->txidind != txidind || memcmp(t->txid.bytes,txid.bytes,sizeof(bits256)) != 0 || t->numvouts != numvouts || t->numvins != numvins || t->firstvout != ramchain->H.unspentind || t->firstvin != ramchain->H.spendind )
        {
            printf("iguana_ramchain_addtxid: addtxid mismatch (%d %d %d %d %d) vs. (%d %d %d %d %d)\n",t->txidind,t->numvouts,t->numvins,t->firstvout,t->firstvin,txidind,numvouts,numvins,ramchain->H.unspentind,ramchain->H.spendind);
            getchar();
            return(0);
        }
    }
    else
    {
        //if ( ramchain->expanded != 0 )
        //    printf("T.%p txidind.%d numvouts.%d numvins.%d\n",T,txidind,numvouts,numvins);
        t->txidind = txidind, t->txid = txid, t->numvouts = numvouts, t->numvins = numvins;
        t->firstvout = ramchain->H.unspentind, t->firstvin = ramchain->H.spendind;
        //if ( txidind <= 2 )
        //    printf("%p TXID.[%d] firstvout.%d/%d firstvin.%d/%d\n",t,txidind,ramchain->unspentind,numvouts,ramchain->spendind,numvins);
    }
    if ( ramchain->expanded != 0 )
    {
        //printf("add hdrsi.%d dest.%p txidind.%d %p\n",ramchain->H.hdrsi,ramchain,txidind,t);
        if ( (ptr= iguana_hashsetPT(ramchain,'T',t->txid.bytes,txidind)) == 0 )
        {
            printf("iguana_ramchain_addtxid error adding txidind\n");
            return(0);
        }
    }
    return(txidind);
}

uint32_t iguana_ramchain_addpkhash(struct iguana_info *coin,RAMCHAIN_FUNC,uint8_t rmd160[20],int32_t flags,uint32_t unspentind)
{
    struct iguana_kvitem *ptr; uint32_t pkind = 0;
    if ( ramchain->expanded != 0 && (ptr= iguana_hashfind(ramchain,'P',rmd160)) == 0 )
    {
        pkind = ramchain->pkind++;
        if ( ramchain->H.ROflag != 0 )
        {
            if ( P[pkind].flags != flags || P[pkind].firstunspentind != unspentind )
            {
                printf("iguana_ramchain_addpkhash pkind.%d error mismatched flags.(%x %x) firstunspentind.%x vs %x\n",pkind,P[pkind].flags,flags,P[pkind].firstunspentind,unspentind);
                return(0);
            }
            if ( memcmp(P[pkind].rmd160,rmd160,sizeof(P[pkind].rmd160)) != 0 )
            {
                printf("iguana_ramchain_addpkhash error mismatched rmd160\n");
                return(0);
            }
        }
        else
        {
            P[pkind].flags = flags;
            P[pkind].firstunspentind = unspentind;
            //printf("%p P[%d] <- firstunspent.%d\n",&P[pkind],pkind,unspentind);
            memcpy(P[pkind].rmd160,rmd160,sizeof(P[pkind].rmd160));
        }
        if ( (ptr= iguana_hashsetPT(ramchain,'P',&P[pkind],pkind)) == 0 )
        {
            printf("iguana_ramchain_addpkhash error adding pkhash\n");
            return(0);
        }
    }
    return(pkind);
}

uint32_t iguana_ramchain_addunspent20(struct iguana_info *coin,RAMCHAIN_FUNC,uint64_t value,uint8_t *script,int32_t scriptlen,bits256 txid,int32_t vout)
{
    //struct iguana_unspent { uint64_t value; uint32_t txidind,pkind,prevunspentind; } __attribute__((packed));
    uint8_t rmd160[20]; uint32_t unspentind; struct iguana_unspent20 *u;
    unspentind = ramchain->H.unspentind++;
    u = &U[unspentind];
    if ( scriptlen == -20 )
        memcpy(rmd160,script,20);
    else iguana_calcrmd160(coin,rmd160,script,scriptlen,txid);
    if ( ramchain->H.ROflag != 0 )
    {
        //printf("%p U[%d] txidind.%d pkind.%d\n",u,unspentind,ramchain->txidind,pkind);
        if ( u->txidind != ramchain->H.txidind || u->value != value || memcmp(u->rmd160,rmd160,sizeof(rmd160)) != 0 )
        {
            printf("iguana_ramchain_addunspent: mismatched values.(%.8f %d) vs (%.8f %d)\n",dstr(u->value),u->txidind,dstr(value),ramchain->H.txidind);
            return(0);
        }
    }
    else
    {
        u->value = value;
        u->txidind = ramchain->H.txidind;
        memcpy(u->rmd160,rmd160,sizeof(rmd160));
    }
    return(unspentind);
}

uint32_t iguana_ramchain_addunspent(struct iguana_info *coin,RAMCHAIN_FUNC,uint64_t value,uint16_t hdrsi,uint8_t *rmd160,uint16_t vout)
{
    //struct iguana_unspent { uint64_t value; uint32_t txidind,pkind,prevunspentind; } __attribute__((packed));
    uint32_t unspentind; struct iguana_unspent *u; struct iguana_kvitem *ptr; int32_t pkind;
    unspentind = ramchain->H.unspentind++;
    u = &Ux[unspentind];
    if ( (ptr= iguana_hashfind(ramchain,'P',rmd160)) == 0 )
        pkind = iguana_ramchain_addpkhash(coin,RAMCHAIN_ARG,rmd160,0,unspentind);
    else pkind = ptr->hh.itemind;
    if ( pkind == 0 )
        return(0);
    if ( ramchain->H.ROflag != 0 )
    {
        //printf("%p U[%d] txidind.%d pkind.%d\n",u,unspentind,ramchain->txidind,pkind);
        if ( u->value != value || u->pkind != pkind || u->value != value || u->txidind != ramchain->H.txidind || (pkind != 0 && u->prevunspentind != A[pkind].lastunspentind) || u->vout != vout || u->hdrsi != hdrsi )
        {
            printf("iguana_ramchain_addunspent: mismatched values.(%d %.8f %d %d) vs (%d %.8f %d %d) %p\n",u->pkind,dstr(u->value),u->txidind,u->prevunspentind,pkind,dstr(value),ramchain->H.txidind,A[pkind].lastunspentind,&A[pkind]);
            return(0);
        }
    }
    else
    {
        u->value = value;
        u->vout = vout, u->hdrsi = hdrsi;
        u->txidind = ramchain->H.txidind, u->pkind = pkind;
        u->prevunspentind = A[pkind].lastunspentind;
    }
    //printf("%p A[%d] last <- U%d\n",&A[pkind],pkind,unspentind);
    A[pkind].balance += value;
    A[pkind].lastunspentind = unspentind;
    return(unspentind);
}

uint32_t iguana_ramchain_addspend256(struct iguana_info *coin,RAMCHAIN_FUNC,bits256 prev_hash,int32_t prev_vout,uint8_t *script,int32_t scriptlen,uint32_t sequence,int32_t hdrsi,int32_t bundlei)
{
    struct iguana_spend256 *s; uint32_t spendind;
    spendind = ramchain->H.spendind++;
    s = &S[spendind];
    if ( ramchain->H.ROflag != 0 )
    {
        if ( (s->diffsequence == 0 && sequence != 0xffffffff) || (s->diffsequence != 0 && sequence == 0xffffffff) || memcmp(s->prevhash2.bytes,prev_hash.bytes,sizeof(bits256)) != 0 || s->prevout != prev_vout )
        {
            char str[65],str2[65]; printf("check addspend.%d v %d RO value mismatch diffseq.%d v %x (%d %d:%d) vs (%d %d:%d) %s vs %s\n",spendind,s->spendind,s->diffsequence,sequence,s->prevout,s->hdrsi,s->bundlei,prev_vout,hdrsi,bundlei,bits256_str(str,s->prevhash2),bits256_str(str2,prev_hash));
            //printf("check addspend.%d vs %d RO value mismatch (%d %d:%d) vs (%d %d:%d)\n",spendind,s->spendind,s->prevout,s->hdrsi,s->bundlei,prev_vout,hdrsi,bundlei);
            getchar();
            return(0);
        }
        //printf(" READ.%p spendind.%d vs %d prevout.%d hdrsi.%d:%d\n",s,spendind,s->spendind,s->prevout,s->hdrsi,s->bundlei);
    }
    else
    {
        if ( sequence != 0xffffffff )
            s->diffsequence = 1;
        s->prevhash2 = prev_hash, s->prevout = prev_vout;
        s->hdrsi = hdrsi, s->bundlei = bundlei;
        s->spendind = spendind;
        //char str[65]; printf("W.%p s.%d vout.%d/%d %d:%d %s\n",s,spendind,s->prevout,prev_vout,s->hdrsi,s->bundlei,bits256_str(str,prev_hash));
    }
    return(spendind);
}

//struct iguana_spend { uint32_t prevspendind,spendtxidind; uint16_t vout,hdrsi:14,external:1,diffsequence:1; } __attribute__((packed)); // dont need nextspend

int32_t iguana_ramchain_txid(struct iguana_info *coin,RAMCHAIN_FUNC,bits256 *txidp,struct iguana_spend *s)
{
    int32_t ind,external;
    memset(txidp,0,sizeof(*txidp));
    //printf("s.%p ramchaintxid vout.%x spendtxidind.%d numexternals.%d isext.%d numspendinds.%d\n",s,s->vout,s->spendtxidind,ramchain->numexternaltxids,s->external,ramchain->numspends);
    if ( s->prevout < 0 )
        return(-1);
    ind = s->spendtxidind;
    external = (ind >> 31) & 1;
    ind &= ~(1 << 31);
    if ( s->external != 0 && s->external == external && ind < ramchain->H.data->numexternaltxids )
    {
        //printf("ind.%d externalind.%d X[%d]\n",ind,ramchain->externalind,ramchain->data->numexternaltxids);
        *txidp = X[ind];
        return(s->prevout);
    }
    else if ( s->external == 0 && s->external == external && ind < ramchain->H.txidind )
    {
        *txidp = T[ind].txid;
        return(s->prevout);
    }
    return(-2);
}

uint32_t iguana_ramchain_addspend(struct iguana_info *coin,RAMCHAIN_FUNC,bits256 prev_hash,int32_t prev_vout,uint32_t sequence,int32_t hdrsi,int32_t bundlei)
{
    struct iguana_spend *s; struct iguana_kvitem *ptr; bits256 txid;
    uint32_t spendind,unspentind,txidind,pkind,external; uint64_t value = 0;
    spendind = ramchain->H.spendind++;
    s = &Sx[spendind];
    pkind = unspentind = 0;
    if ( (ptr= iguana_hashfind(ramchain,'T',prev_hash.bytes)) == 0 )
    {
        external = 1;
        txidind = ramchain->externalind++;
        //char str[65]; printf("X[%d] <- %s\n",txidind,bits256_str(str,prev_hash));
        if ( ramchain->H.ROflag != 0 )
        {
            if ( memcmp(X[txidind].bytes,prev_hash.bytes,sizeof(prev_hash)) != 0 )
            {
                char str[65],str2[65]; printf("iguana_ramchain_addspend X[%d] cmperror %s vs %s\n",txidind,bits256_str(str,X[txidind]),bits256_str(str2,prev_hash));
                return(0);
            }
        } else X[txidind] = prev_hash;
        if ( (ptr= iguana_hashsetPT(ramchain,'T',&X[txidind].bytes,txidind | (1 << 31))) == 0 )
        {
            printf("iguana_ramchain_addspend error adding external\n");
            return(0);
        }
        txidind |= (1 << 31);
    } else txidind = ptr->hh.itemind;
    if ( (external= ((txidind >> 31) & 1)) == 0 )
    {
        if ( txidind > 0 && txidind < ramchain->H.data->numtxids )
        {
            if ( (unspentind= T[txidind].firstvout + prev_vout) > 0 && unspentind < ramchain->H.data->numunspents )
            {
                value = Ux[unspentind].value;
                if ( (pkind= Ux[unspentind].pkind) == 0 || pkind >= ramchain->H.data->numpkinds )
                {
                    printf("spendind.%d -> unspendind.%d %.8f -> pkind.0x%x\n",spendind,unspentind,dstr(value),pkind);
                    return(0);
                }
            } else printf("addspend illegal unspentind.%d vs %d\n",unspentind,ramchain->H.data->numunspents);
        } else printf("addspend illegal txidind.%d vs %d\n",txidind,ramchain->H.data->numtxids);
    }
    if ( ramchain->H.ROflag != 0 )
    {
        iguana_ramchain_txid(coin,RAMCHAIN_ARG,&txid,s);
        if ( (s->diffsequence == 0 && sequence != 0xffffffff) || (s->diffsequence != 0 && sequence == 0xffffffff) || memcmp(txid.bytes,prev_hash.bytes,sizeof(bits256)) != 0 || s->prevout != prev_vout )
        {
            char str[65],str2[65]; printf("ramchain_addspend RO value mismatch diffseq.%d v %x (%d %d) vs (%d %d) %s vs %s\n",s->diffsequence,sequence,s->prevout,s->bundlei,prev_vout,bundlei,bits256_str(str,txid),bits256_str(str2,prev_hash));
            return(0);
        }
    }
    else
    {
        if ( sequence != 0xffffffff )
            s->diffsequence = 1;
        s->external = external, s->spendtxidind = txidind,
        s->prevout = prev_vout;
        //char str[65]; printf("%s set prevout.%d -> %d\n",bits256_str(str,prev_hash),prev_vout,s->prevout);
        if ( pkind != 0 )
            s->prevspendind = A[pkind].lastspendind;
        s->bundlei = bundlei;
    }
    if ( pkind != 0 )
    {
        A[pkind].balance -= value;
        A[pkind].lastspendind = spendind;
        if ( P2[pkind].firstspendind == 0 )
            P2[pkind].firstspendind = spendind;
    }
    if ( unspentind != 0 )
    {
        if ( U2[unspentind].spendind == 0 )
            U2[unspentind].spendind = spendind;
    }
    return(spendind);
}

void _iguana_ramchain_setptrs(RAMCHAIN_PTRPS)
{
    *T = (void *)((long)ramchain->H.data + (long)ramchain->H.data->Toffset);
    if ( ramchain->expanded != 0 )
    {
        *Ux = (void *)((long)ramchain->H.data + (long)ramchain->H.data->Uoffset);
        *Sx = (void *)((long)ramchain->H.data + (long)ramchain->H.data->Soffset);
        *P = (void *)((long)ramchain->H.data + (long)ramchain->H.data->Poffset);
        *X = (void *)((long)ramchain->H.data + (long)ramchain->H.data->Xoffset);
        ramchain->roU2 = (void *)((long)ramchain->H.data + (long)ramchain->H.data->U2offset);
        ramchain->roP2 = (void *)((long)ramchain->H.data + (long)ramchain->H.data->P2offset);
        ramchain->roA = (void *)((long)ramchain->H.data + (long)ramchain->H.data->Aoffset);
        if ( (*U2= ramchain->U2) == 0 )
            *U2 = ramchain->U2 = ramchain->roU2;
        if ( (*P2= ramchain->P2) == 0 )
            *P2 = ramchain->P2 = ramchain->roP2;
        if ( (*A= ramchain->A) == 0 )
            *A = ramchain->A = ramchain->roA;
        //printf("T.%p Ux.%p Sx.%p P.%p\n",*T,*Ux,*Sx,*P);
        *U = 0, *S = 0;
    }
    else
    {
        *U = (void *)((long)ramchain->H.data + (long)ramchain->H.data->Uoffset);
        *S = (void *)((long)ramchain->H.data + (long)ramchain->H.data->Soffset);
        *Ux = 0, *Sx = 0, *P = 0, *X = 0, *U2 = 0, *P2 = 0, *A = 0;
    }
}

int64_t iguana_ramchain_init(struct iguana_ramchain *ramchain,struct iguana_memspace *mem,struct iguana_memspace *hashmem,int32_t firsti,int32_t numtxids,int32_t numunspents,int32_t numspends,int32_t numpkinds,int32_t numexternaltxids,int32_t expanded)
{
    int64_t offset = 0;
    if ( mem == 0 )
        return(0);
    memset(ramchain,0,sizeof(*ramchain));
    ramchain->expanded = (expanded != 0);
    if ( (ramchain->hashmem= hashmem) != 0 )
        iguana_memreset(hashmem);
    ramchain->H.data = mem->ptr, offset += sizeof(struct iguana_ramchaindata);
    if ( (ramchain->H.data->firsti= firsti) != 0 )
    {
        numtxids++, numunspents++, numspends++;
        if ( numpkinds != 0 )
            numpkinds++;
    }
    ramchain->H.data->Toffset = offset, offset += (sizeof(struct iguana_txid) * numtxids);
    if ( ramchain->expanded != 0 )
    {
        if ( numexternaltxids == 0 )
            numexternaltxids = numspends;
        if ( numpkinds == 0 )
            numpkinds = numunspents;
        ramchain->H.data->Uoffset = offset, offset += (sizeof(struct iguana_unspent) * numunspents);
        ramchain->H.data->Soffset = offset, offset += (sizeof(struct iguana_spend) * numspends);
        ramchain->H.data->Poffset = offset, offset += (sizeof(struct iguana_pkhash) * numpkinds);
        ramchain->H.data->U2offset = offset, offset += (sizeof(struct iguana_Uextra) * numunspents);
        ramchain->H.data->P2offset = offset, offset += (sizeof(struct iguana_pkextra) * numpkinds);
        ramchain->H.data->Aoffset = offset, offset += (sizeof(struct iguana_account) * numpkinds);
        ramchain->H.data->Xoffset = offset, offset += (sizeof(bits256) * numexternaltxids);
    }
    else
    {
        ramchain->H.data->Uoffset = offset, offset += (sizeof(struct iguana_unspent20) * numunspents);
        ramchain->H.data->Soffset = offset, offset += (sizeof(struct iguana_spend256) * numspends);
    }
    if ( offset < mem->totalsize )
        iguana_memreset(mem);
    else
    {
        printf("NEED %ld realloc for %ld\n",(long)offset,(long)mem->totalsize);
        getchar();
        iguana_mempurge(mem);
        iguana_meminit(mem,"ramchain",0,offset,0);
    }
    ramchain->H.data->numtxids = numtxids;
    ramchain->H.data->numunspents = numunspents;
    ramchain->H.data->numspends = numspends;
    ramchain->H.data->numpkinds = numpkinds;
    ramchain->H.data->numexternaltxids = numexternaltxids;
    //printf("init.(%d %d %d %d %d)\n",numtxids,numunspents,numspends,numpkinds,numexternaltxids);
    return(offset);
}

int64_t iguana_ramchain_size(struct iguana_ramchain *ramchain)
{
    struct iguana_ramchaindata *rdata; int64_t offset = sizeof(struct iguana_ramchaindata);
    if ( (rdata= ramchain->H.data) != 0 )
    {
        offset += (sizeof(struct iguana_txid) * rdata->numtxids);
        if ( ramchain->expanded != 0 )
        {
            offset += (sizeof(struct iguana_unspent) * rdata->numunspents);
            offset += (sizeof(struct iguana_spend) * rdata->numspends);
            offset += (sizeof(struct iguana_pkhash) * rdata->numpkinds);
            offset += (sizeof(struct iguana_Uextra) * rdata->numunspents);
            offset += (sizeof(struct iguana_pkextra) * rdata->numpkinds);
            offset += (sizeof(struct iguana_account) * rdata->numpkinds);
            offset += (sizeof(bits256) * rdata->numexternaltxids);
        }
        else
        {
            offset += (sizeof(struct iguana_unspent20) * rdata->numunspents);
            offset += (sizeof(struct iguana_spend256) * rdata->numspends);
        }
    }
    return(offset);
}

long iguana_ramchain_save(struct iguana_info *coin,RAMCHAIN_FUNC,uint32_t ipbits,bits256 hash2,int32_t bundlei)
{
    struct iguana_ramchaindata *rdata,tmp;
    char fname[1024]; long fpos = -1; int32_t hdrsi,checki; int64_t offset; FILE *fp;
    if ( (rdata= ramchain->H.data) == 0 )
        return(-1);
    if ( (checki= iguana_peerfname(coin,&hdrsi,ipbits==0?"DB":"tmp",fname,ipbits,hash2)) != bundlei || bundlei < 0 || bundlei >= coin->chain->bundlesize )
    {
        printf(" wont save.(%s) bundlei.%d != checki.%d\n",fname,bundlei,checki);
        return(-1);
    }
    if ( (fp= fopen(fname,"rb+")) == 0 )
    {
        if ( (fp= fopen(fname,"wb")) != 0 )
            coin->peers.numfiles++;
    } else fseek(fp,0,SEEK_END);
    if ( fp != 0 )
    {
        tmp = *rdata;
        fpos = ftell(fp);
        offset = sizeof(*rdata);
        rdata->Toffset = offset, offset += (sizeof(struct iguana_txid) * rdata->numtxids);
        if ( rdata->numblocks > 1 )
        {
            rdata->Uoffset = offset, offset += (sizeof(struct iguana_unspent) * rdata->numunspents);
            rdata->Soffset = offset, offset += (sizeof(struct iguana_spend) * rdata->numspends);
            rdata->Poffset = offset, offset += (sizeof(struct iguana_pkhash) * rdata->numpkinds);
            rdata->U2offset = offset, offset += (sizeof(struct iguana_Uextra) * rdata->numunspents);
            rdata->P2offset = offset, offset += (sizeof(struct iguana_pkextra) * rdata->numpkinds);
            rdata->Aoffset = offset, offset += (sizeof(struct iguana_account) * rdata->numpkinds);
            rdata->Xoffset = offset, offset += (sizeof(bits256) * rdata->numexternaltxids);
        }
        else
        {
            rdata->Uoffset = offset, offset += (sizeof(struct iguana_unspent20) * rdata->numunspents);
            rdata->Soffset = offset, offset += (sizeof(struct iguana_spend256) * rdata->numspends);
        }
        rdata->allocsize = offset;
        fwrite(rdata,1,sizeof(*rdata),fp);
        *rdata = tmp;
        fwrite(T,sizeof(struct iguana_txid),rdata->numtxids,fp);
        //printf("fwrite P[%d] (%x %x) (%x %x)\n",(int32_t)ramchain->data->Poffset,P[1].firstunspentind,P[1].flags,P[2].firstunspentind,P[2].flags);
        if ( ramchain->expanded != 0 )
        {
            fwrite(Ux,sizeof(struct iguana_unspent),rdata->numunspents,fp);
            fwrite(Sx,sizeof(struct iguana_spend),rdata->numspends,fp);
            fwrite(P,sizeof(struct iguana_pkhash),rdata->numpkinds,fp);
            fwrite(U2,sizeof(struct iguana_Uextra),rdata->numunspents,fp);
            fwrite(P2,sizeof(struct iguana_pkextra),rdata->numpkinds,fp);
            fwrite(A,sizeof(struct iguana_account),rdata->numpkinds,fp);
            fwrite(X,sizeof(bits256),rdata->numexternaltxids,fp);
            //printf("iguana_ramchain_save:  (%ld - %ld) diff.%ld vs %ld [%ld]\n",ftell(fp),(long)fpos,(long)(ftell(fp) - fpos),(long)rdata->allocsize,(long)(ftell(fp) - fpos) - (long)rdata->allocsize);
        }
        else
        {
            fwrite(U,sizeof(struct iguana_unspent20),rdata->numunspents,fp);
            fwrite(S,sizeof(struct iguana_spend256),rdata->numspends,fp);
        }
        if ( (ftell(fp) - fpos) != rdata->allocsize )
            fpos = -1;
        //int32_t i; char str[65];
        //for (i=0; i<rdata->numexternaltxids; i++)
        //    printf("X[%d] %s\n",i,bits256_str(str,X[i]));
        fclose(fp);
    }
    return(fpos);
}

int32_t iguana_ramchain_verify(struct iguana_info *coin,struct iguana_ramchain *ramchain)
{
    RAMCHAIN_DECLARE; struct iguana_txid *t; struct iguana_unspent *u; struct iguana_pkhash *p;
    struct iguana_ramchaindata *rdata; int32_t k,pkind,vout; struct iguana_kvitem *ptr; bits256 txid;
    // iguana_txid { bits256 txid; uint32_t txidind,firstvout,firstvin; uint16_t numvouts,numvins;}
    if ( (rdata= ramchain->H.data) == 0 )
        return(-100);
    _iguana_ramchain_setptrs(RAMCHAIN_PTRS);
    ramchain->pkind = ramchain->H.unspentind = ramchain->H.spendind = rdata->firsti;
    ramchain->externalind = 0;
    for (ramchain->H.txidind=rdata->firsti; ramchain->H.txidind<rdata->numtxids; ramchain->H.txidind++)
    {
        t = &T[ramchain->H.txidind];
        if ( t->txidind != ramchain->H.txidind )
        {
            printf("firsti.%d  t->txidind.%d != txidind.%d\n",rdata->firsti,t->txidind,ramchain->H.txidind);
            return(-1);
        }
        if ( t->firstvout != ramchain->H.unspentind )
        {
            printf("%p txidind.%d firstvout.%d != unspentind.%d\n",t,ramchain->H.txidind,t->firstvout,ramchain->H.unspentind);
            getchar();
            return(-4);
        }
        if ( t->firstvin != ramchain->H.spendind )
        {
            printf("t[%d] firstvin.%d vs spendind.%d\n",t->txidind,t->firstvin,ramchain->H.spendind);
            return(-5);
        }
        if ( ramchain->expanded != 0 )
        {
            if ( (ptr= iguana_hashfind(ramchain,'T',t->txid.bytes)) == 0 )
                return(-2);
            if ( ptr->hh.itemind != ramchain->H.txidind )
                return(-3);
            for (k=0; k<t->numvouts; k++,ramchain->H.unspentind++)
            {
                u = &Ux[ramchain->H.unspentind];
                if ( u->txidind != ramchain->H.txidind )
                {
                    printf(" k.%d %p U.%d u->txidind.%x != txidind.%d\n",k,u,ramchain->H.unspentind,u->txidind,ramchain->H.txidind);
                    return(-6);
                }
                if ( (pkind= u->pkind) < 0 || pkind >= rdata->numpkinds )
                {
                    printf("k.%d unspentind.%d pkind.%d numpkinds.%d\n",k,ramchain->H.unspentind,pkind,rdata->numpkinds);
                    return(-7);
                }
                p = &P[pkind];
                if ( (ptr= iguana_hashfind(ramchain,'P',p->rmd160)) == 0 )
                    return(-8);
                if ( ptr->hh.itemind == pkind && p->firstunspentind > ramchain->H.unspentind )
                {
                    printf("%p itemind.%d pkind.%d firstunspent.%d != %d unspentind?\n",p,ptr->hh.itemind,pkind,p->firstunspentind,ramchain->H.unspentind);
                    return(-9);
                }
            }
        }
        else
        {
            for (k=0; k<t->numvouts; k++,ramchain->H.unspentind++)
            {
                if ( U[ramchain->H.unspentind].txidind != ramchain->H.txidind )
                {
                    printf(" k.%d U.%d u->txidind.%x != txidind.%d\n",k,ramchain->H.unspentind,U[ramchain->H.unspentind].txidind,ramchain->H.txidind);
                    return(-6);
                }
            }
        }
        ramchain->H.spendind += t->numvins;
    }
    ramchain->H.spendind = rdata->firsti;
    for (ramchain->H.txidind=rdata->firsti; ramchain->H.txidind<rdata->numtxids; ramchain->H.txidind++)
    {
        t = &T[ramchain->H.txidind];
        for (k=0; k<t->numvins; k++,ramchain->H.spendind++)
        {
            if ( ramchain->expanded != 0 )
            {
                //printf("item.%p [%d] X.%p k.%d txidind.%d/%d spendind.%d/%d s->txidind.%x/v%d\n",rdata,rdata->numexternaltxids,X,k,ramchain->txidind,rdata->numtxids,spendind,rdata->numspends,s->spendtxidind,s->vout);
                if ( (vout= iguana_ramchain_txid(coin,RAMCHAIN_ARG,&txid,&Sx[ramchain->H.spendind])) < -1 )
                {
                    printf("txidind.%d k.%d error getting txid firsti.%d X.%d vout.%d spend.%x/%d numX.%d numT.%d\n",ramchain->H.txidind,k,rdata->firsti,ramchain->externalind,vout,Sx[ramchain->H.spendind].spendtxidind,rdata->numspends,rdata->numexternaltxids,rdata->numtxids);
                    return(-10);
                }
                if ( vout == -1 )
                {
                    // mining output
                }
                else
                {
                    if ( (ptr= iguana_hashfind(ramchain,'T',txid.bytes)) == 0 )
                    {
                        char str[65]; printf("cant find vout.%d %s\n",vout,bits256_str(str,txid));
                        return(-11);
                    }
                }
            }
        }
    }
    if ( ramchain->expanded != 0 && ramchain->A != ramchain->roA )
    {
        for (k=rdata->firsti; k<rdata->numpkinds; k++)
        {
            if ( memcmp(&ramchain->A[k],&ramchain->roA[k],sizeof(ramchain->A[k])) != 0 )
                return(-14);
            if ( memcmp(&ramchain->P2[k],&ramchain->roP2[k],sizeof(ramchain->P2[k])) != 0 )
                return(-15);
        }
        for (k=rdata->firsti; k<rdata->numunspents; k++)
            if ( memcmp(&ramchain->U2[k],&ramchain->roU2[k],sizeof(ramchain->U2[k])) != 0 )
                return(-16);
    }
    return(0);
}

int32_t iguana_ramchain_free(struct iguana_ramchain *ramchain,int32_t deleteflag)
{
    struct iguana_kvitem *item,*tmp;
    if ( ramchain->H.ROflag != 0 && ramchain->hashmem == 0 )
    {
        //printf("Free A %p %p, U2, P2\n",ramchain->A,ramchain->roA);
        if ( ramchain->A != ramchain->roA )
            myfree(ramchain->A,sizeof(*ramchain->A) * ramchain->H.data->numpkinds), ramchain->A = 0;
        if ( ramchain->U2 != ramchain->roU2 )
            myfree(ramchain->U2,sizeof(*ramchain->U2) * ramchain->H.data->numunspents), ramchain->U2 = 0;
        if ( ramchain->P2 != ramchain->roP2 )
            myfree(ramchain->P2,sizeof(*ramchain->P2) * ramchain->H.data->numpkinds), ramchain->P2 = 0;
    }
    if ( deleteflag != 0 )
    {
        if ( ramchain->txids != 0 )
        {
            HASH_ITER(hh,ramchain->txids,item,tmp)
            {
                HASH_DEL(ramchain->txids,item);
            }
        }
        if ( ramchain->pkhashes != 0 )
        {
            HASH_ITER(hh,ramchain->pkhashes,item,tmp)
            {
                HASH_DEL(ramchain->pkhashes,item);
            }
        }
    }
    if ( ramchain->hashmem != 0 )
        iguana_memreset(ramchain->hashmem);
    if ( ramchain->filesize != 0 )
        munmap(ramchain->fileptr,ramchain->filesize);
    memset(ramchain,0,sizeof(*ramchain));
    return(0);
}

void iguana_ramchain_extras(struct iguana_ramchain *ramchain,struct iguana_memspace *hashmem)
{
    RAMCHAIN_DECLARE;
    if ( ramchain->expanded != 0 )
    {
        _iguana_ramchain_setptrs(RAMCHAIN_PTRS);
        if ( (ramchain->hashmem= hashmem) != 0 )
            iguana_memreset(hashmem);
        ramchain->A = (hashmem != 0) ? iguana_memalloc(hashmem,sizeof(struct iguana_account) * ramchain->H.data->numpkinds,1) : mycalloc('p',ramchain->H.data->numpkinds,sizeof(struct iguana_account));
        ramchain->P2 = (hashmem != 0) ? iguana_memalloc(hashmem,sizeof(struct iguana_pkextra) * ramchain->H.data->numpkinds,1) : mycalloc('2',ramchain->H.data->numpkinds,sizeof(struct iguana_pkextra));
        ramchain->U2 = (hashmem != 0) ? iguana_memalloc(hashmem,sizeof(struct iguana_Uextra) * ramchain->H.data->numunspents,1) : mycalloc('3',ramchain->H.data->numunspents,sizeof(struct iguana_Uextra));
        //printf("iguana_ramchain_extras A.%p:%p U2.%p:%p P2.%p:%p\n",ramchain->A,ramchain->roA,ramchain->U2,ramchain->roU2,ramchain->P2,ramchain->roP2);
        memcpy(ramchain->U2,ramchain->roU2,sizeof(*ramchain->U2) * ramchain->H.data->numunspents);
        memcpy(ramchain->P2,ramchain->roP2,sizeof(*ramchain->P2) * ramchain->H.data->numpkinds);
    }
}

struct iguana_ramchain *iguana_ramchain_map(struct iguana_info *coin,struct iguana_ramchain *ramchain,struct iguana_memspace *hashmem,uint32_t ipbits,bits256 hash2,int32_t bundlei,long fpos,int32_t allocextras)
{
    int32_t checki,hdrsi; char fname[1024],str[65],str2[65]; long filesize; void *ptr;
    if ( ramchain->fileptr == 0 || ramchain->filesize <= 0 )
    {
        if ( (checki= iguana_peerfname(coin,&hdrsi,ipbits==0?"DB":"tmp",fname,ipbits,hash2)) != bundlei || bundlei < 0 || bundlei >= coin->chain->bundlesize )
        {
            printf("iguana_ramchain_map.(%s) illegal hdrsi.%d bundlei.%d\n",fname,hdrsi,bundlei);
            return(0);
        }
        memset(ramchain,0,sizeof(*ramchain));
        if ( (ptr= map_file(fname,&filesize,0)) == 0 )
            return(0);
        ramchain->fileptr = ptr;
        ramchain->filesize = (long)filesize;
    }
    if ( ramchain->fileptr != 0 && ramchain->filesize > 0 )
    {
        ramchain->H.data = (void *)((long)ramchain->fileptr + ramchain->filesize);
        ramchain->H.ROflag = 1;
        //printf("ptr.%p %p mapped P[%d] fpos.%d + %ld -> %ld vs %ld\n",ptr,ramchain->data,(int32_t)ramchain->data->Poffset,(int32_t)fpos,(long)ramchain->data->allocsize,(long)(fpos + ramchain->data->allocsize),filesize);
        if ( iguana_ramchain_size(ramchain) != ramchain->H.data->allocsize || fpos+ramchain->H.data->allocsize > filesize )
        {
            printf("iguana_ramchain_map.(%s) size mismatch %ld vs %ld vs filesize.%ld\n",fname,(long)iguana_ramchain_size(ramchain),(long)ramchain->H.data->allocsize,(long)filesize);
            munmap(ramchain->fileptr,ramchain->filesize);
            return(0);
        }
        else if ( memcmp(hash2.bytes,ramchain->H.data->firsthash2.bytes,sizeof(bits256)) != 0 )
        {
            printf("iguana_ramchain_map.(%s) hash2 mismatch %s vs %s\n",fname,bits256_str(str,hash2),bits256_str(str2,ramchain->H.data->firsthash2));
            munmap(ramchain->fileptr,ramchain->filesize);
            return(0);
        }
        else if ( ramchain->H.data->numblocks > 1 )
        {
            if ( allocextras != 0 )
                iguana_ramchain_extras(ramchain,hashmem);
        }
        return(ramchain);
    } else printf("iguana_ramchain_map.(%s) cant map file\n",fname);
    return(0);
}

void iguana_ramchain_link(struct iguana_ramchain *ramchain,bits256 firsthash2,bits256 lasthash2,int32_t hdrsi,int32_t height,int32_t bundlei,int32_t numblocks,int32_t firsti,int32_t ROflag)
{
    if ( ROflag == 0 )
    {
        ramchain->H.data->firsthash2 = firsthash2;
        ramchain->H.data->lasthash2 = lasthash2;
        ramchain->H.data->hdrsi = hdrsi;
        ramchain->H.data->height = height;
        ramchain->H.data->numblocks = numblocks;
    }
    ramchain->H.hdrsi = hdrsi;
    ramchain->H.bundlei = bundlei;
    ramchain->height = height;
    ramchain->numblocks = numblocks;
    ramchain->H.txidind = ramchain->H.unspentind = ramchain->H.spendind = ramchain->pkind = firsti;
    ramchain->externalind = 0;
}

int32_t iguana_ramchain_cmp(struct iguana_ramchain *A,struct iguana_ramchain *B,int32_t deepflag)
{
    int32_t i; char str[65],str2[65];
    struct iguana_txid *Ta,*Tb; struct iguana_unspent20 *Ua,*Ub; struct iguana_spend256 *Sa,*Sb;
    struct iguana_pkhash *Pa,*Pb; bits256 *Xa,*Xb; struct iguana_Uextra *U2a,*U2b;
    struct iguana_pkextra *P2a,*P2b; struct iguana_account *ACCTa,*ACCTb; struct iguana_unspent *Uxa,*Uxb;
    struct iguana_spend *Sxa,*Sxb;
    
    if ( A->H.data != 0 && B->H.data != 0 && A->H.data->numblocks == B->H.data->numblocks && memcmp(A->H.data->firsthash2.bytes,B->H.data->firsthash2.bytes,sizeof(A->H.data->firsthash2)) == 0 )
    {
        if ( A->H.data->firsti == B->H.data->firsti && A->H.data->numtxids == B->H.data->numtxids && A->H.data->numunspents == B->H.data->numunspents && A->H.data->numspends == B->H.data->numspends && A->H.data->numpkinds == B->H.data->numpkinds && A->H.data->numexternaltxids == B->H.data->numexternaltxids )
        {
            _iguana_ramchain_setptrs(A,&Ta,&Ua,&U2a,&Sa,&Pa,&P2a,&ACCTa,&Xa,&Uxa,&Sxa);
            _iguana_ramchain_setptrs(B,&Tb,&Ub,&U2b,&Sb,&Pb,&P2b,&ACCTb,&Xb,&Uxb,&Sxb);
            for (i=A->H.data->firsti; i<A->H.data->numtxids; i++)
                if ( memcmp(&Ta[i],&Tb[i],sizeof(Ta[i])) != 0 )
                    return(-2);
            if ( A->numblocks > 1 )
            {
                for (i=A->H.data->firsti; i<A->H.data->numspends; i++)
                    if ( memcmp(&Sxa[i],&Sxb[i],sizeof(Sxa[i])) != 0 )
                        return(-3);
                for (i=A->H.data->firsti; i<A->H.data->numunspents; i++)
                {
                    if ( memcmp(&Uxa[i],&Uxb[i],sizeof(Uxa[i])) != 0 )
                        return(-4);
                    if ( memcmp(&U2a[i],&U2b[i],sizeof(U2a[i])) != 0 )
                        return(-5);
                }
                for (i=A->H.data->firsti; i<A->H.data->numpkinds; i++)
                {
                    if ( memcmp(&P2a[i],&P2b[i],sizeof(P2a[i])) != 0 )
                        return(-6);
                    if ( memcmp(&ACCTa[i],&ACCTb[i],sizeof(ACCTa[i])) != 0 )
                        return(-7);
                }
                for (i=0; i<A->H.data->numexternaltxids; i++)
                    if ( memcmp(&Xa[i],&Xb[i],sizeof(Xa[i])) != 0 )
                    {
                        bits256_str(str2,Xb[i]);
                        bits256_str(str,Xa[i]);
                        printf("X[%d] A.%s B.%s\n",i,str,str2);
                        return(-8);
                    }
            }
            else
            {
                for (i=A->H.data->firsti; i<A->H.data->numspends; i++)
                    if ( memcmp(&Sa[i],&Sb[i],sizeof(Sa[i])) != 0 )
                        return(-9);
                for (i=A->H.data->firsti; i<A->H.data->numunspents; i++)
                    if ( memcmp(&Ua[i],&Ub[i],sizeof(Ua[i])) != 0 )
                        return(-10);
            }
        }
        return(0);
    }
    printf("cmp %p %p, numblocks %d:%d %d:%d %s %s\n",A->H.data,B->H.data,A->numblocks,A->H.data->numblocks,B->numblocks,B->H.data->numblocks,bits256_str(str,A->H.data->firsthash2),bits256_str(str2,B->H.data->firsthash2));
    return(-1);
}

int32_t iguana_ramchain_iterate(struct iguana_info *coin,struct iguana_ramchain *dest,struct iguana_ramchain *ramchain)
{
    RAMCHAIN_DECLARE; RAMCHAIN_DESTDECLARE;
    int32_t j,prevout,bundlei; uint32_t spendind,sequence; bits256 prevhash; uint64_t value;
    struct iguana_txid *tx; struct iguana_ramchaindata *rdata; uint8_t *rmd160; struct iguana_unspent *u;
    if ( dest != 0 )
        _iguana_ramchain_setptrs(RAMCHAIN_DESTPTRS);
    _iguana_ramchain_setptrs(RAMCHAIN_PTRS);
    if ( (rdata= ramchain->H.data) == 0 )
        return(-1);
    ramchain->H.ROflag = 1;
    ramchain->H.unspentind = ramchain->H.spendind = ramchain->pkind = rdata->firsti;
    ramchain->externalind = 0;
    for (ramchain->H.txidind=rdata->firsti; ramchain->H.txidind<rdata->numtxids; ramchain->H.txidind++)
    {
        if ( ramchain->expanded != 0 )
            printf("ITER TXID.%d -> dest.%p desttxid.%d\n",ramchain->H.txidind,dest,dest->H.txidind);
        tx = &T[ramchain->H.txidind];
        if ( iguana_ramchain_addtxid(coin,RAMCHAIN_ARG,tx->txid,tx->numvouts,tx->numvins) == 0 )
            return(-1);
        if ( dest != 0 )
        {
            if ( iguana_ramchain_addtxid(coin,RAMCHAIN_DESTARG,tx->txid,tx->numvouts,tx->numvins) == 0 )
                return(-2);
        }
        for (j=0; j<tx->numvouts; j++)
        {
            //printf("unspentind.%d pkind.%d\n",ramchain->unspentind,U[ramchain->unspentind].pkind);
            if ( ramchain->H.unspentind < rdata->numunspents )
            {
                if ( ramchain->expanded != 0 )
                {
                    u = &Ux[ramchain->H.unspentind];
                    value = u->value;
                    if ( u->pkind < rdata->numpkinds )
                    {
                        rmd160 = P[u->pkind].rmd160;
                        if ( iguana_ramchain_addunspent(coin,RAMCHAIN_ARG,value,rdata->hdrsi,rmd160,j) == 0 )
                            return(-3);
                    }
                }
                else
                {
                    value = U[ramchain->H.unspentind].value;
                    rmd160 = U[ramchain->H.unspentind].rmd160;
                    if ( iguana_ramchain_addunspent20(coin,RAMCHAIN_ARG,value,rmd160,-20,tx->txid,j) == 0 )
                        return(-4);
                }
                if ( dest != 0 )
                {
                    if ( iguana_ramchain_addunspent(coin,RAMCHAIN_DESTARG,value,rdata->hdrsi,rmd160,j) == 0 )
                        return(-5);
                }
            } else return(-6);
        }
        ramchain->H.spendind += tx->numvins;
        if ( dest != 0 )
            dest->H.txidind++;
    }
    ramchain->H.txidind = ramchain->H.spendind = rdata->firsti;
    for (ramchain->H.txidind=rdata->firsti; ramchain->H.txidind<rdata->numtxids; ramchain->H.txidind++)
    {
        tx = &T[ramchain->H.txidind];
        for (j=0; j<tx->numvins; j++)
        {
            if ( ramchain->expanded != 0 )
            {
                sequence = (Sx[spendind].diffsequence == 0) ? 0xffffffff : 0;
                prevout = iguana_ramchain_txid(coin,RAMCHAIN_ARG,&prevhash,&Sx[j]);
                bundlei = Sx[spendind].bundlei;
                //char str[65]; printf("vin.%d %s vout.%d\n",j,bits256_str(str,prevhash),prevout);
                if ( iguana_ramchain_addspend(coin,RAMCHAIN_ARG,prevhash,prevout,sequence,rdata->hdrsi,bundlei) == 0 )
                    return(-7);
            }
            else
            {
                spendind = (tx->firstvin + j);
                sequence = (S[spendind].diffsequence == 0) ? 0xffffffff : 0;
                prevhash = S[spendind].prevhash2;
                prevout = S[spendind].prevout;
                bundlei = S[spendind].bundlei;
                if ( iguana_ramchain_addspend256(coin,RAMCHAIN_ARG,prevhash,prevout,0,0,sequence,rdata->hdrsi,bundlei) == 0 )
                    return(-8);
            }
            if ( dest != 0 )
            {
                if ( iguana_ramchain_addspend(coin,RAMCHAIN_DESTARG,prevhash,prevout,sequence,rdata->hdrsi,bundlei) == 0 )
                    return(-9);
            }
        }
        if ( dest != 0 )
            dest->H.txidind++;
    }
    return(0);
}

long iguana_ramchain_setsize(struct iguana_ramchain *ramchain)
{
    ramchain->H.data->numtxids = ramchain->H.txidind;
    ramchain->H.data->numunspents = ramchain->H.unspentind;
    ramchain->H.data->numspends = ramchain->H.spendind;
    ramchain->H.data->numpkinds = ramchain->pkind;
    ramchain->H.data->numexternaltxids = ramchain->externalind;
    ramchain->H.data->allocsize = iguana_ramchain_size(ramchain);
    return((long)ramchain->H.data->allocsize);
}

long iguana_ramchain_data(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_txblock *origtxdata,struct iguana_msgtx *txarray,int32_t txn_count,uint8_t *data,int32_t recvlen)
{
    RAMCHAIN_DECLARE; long fsize; void *ptr; struct iguana_ramchain R,*mapchain,*ramchain = &addr->ramchain;
    struct iguana_msgtx *tx; int32_t i,j,firsti=1,err,flag,bundlei = -2; struct iguana_bundle *bp = 0;
    if ( iguana_bundlefind(coin,&bp,&bundlei,origtxdata->block.hash2) == 0 )
        return(-1);
    if ( bp->fpos[bundlei] >= 0 )
        return(bp->fpos[bundlei]);
    SETBIT(bp->recv,bundlei);
    bp->fpos[bundlei] = -1;
    bp->recvlens[bundlei] = recvlen;
    if ( iguana_ramchain_init(ramchain,&addr->TXDATA,&addr->HASHMEM,1,txn_count,origtxdata->numunspents,origtxdata->numspends,0,0,0) == 0 )
        return(-1);
    iguana_ramchain_link(ramchain,origtxdata->block.hash2,origtxdata->block.hash2,bp->hdrsi,bp->bundleheight+bundlei,bundlei,1,firsti,0);
    _iguana_ramchain_setptrs(RAMCHAIN_PTRS);
    if ( T == 0 || U == 0 || S == 0 )// P == 0//|| X == 0 || A == 0 || U2 == 0 || P2 == 0 )
    {
        printf("fatal error getting txdataptrs\n");
        return(-1);
    }
    for (i=0; i<txn_count; i++,ramchain->H.txidind++)
    {
        tx = &txarray[i];
        iguana_ramchain_addtxid(coin,RAMCHAIN_ARG,tx->txid,tx->tx_out,tx->tx_in);
        for (j=0; j<tx->tx_out; j++)
        {
            iguana_ramchain_addunspent20(coin,RAMCHAIN_ARG,tx->vouts[j].value,tx->vouts[j].pk_script,tx->vouts[j].pk_scriptlen,tx->txid,j);
        }
        ramchain->H.spendind += tx->tx_in;
    }
    ramchain->H.txidind = ramchain->H.spendind = ramchain->H.data->firsti;
    for (i=0; i<txn_count; i++,ramchain->H.txidind++)
    {
        tx = &txarray[i];
        for (j=0; j<tx->tx_in; j++)
        {
            //char str[65]; printf("PT vin.%d %s vout.%d\n",j,bits256_str(str,tx->vins[j].prev_hash),tx->vins[j].prev_vout);
            iguana_ramchain_addspend256(coin,RAMCHAIN_ARG,tx->vins[j].prev_hash,tx->vins[j].prev_vout,tx->vins[j].script,tx->vins[j].scriptlen,tx->vins[j].sequence,bp->hdrsi,bundlei);
        }
    }
    iguana_ramchain_setsize(ramchain);
    flag = 0;
    //char str[65]; printf("height.%d num.%d:%d T.%d U.%d S.%d P.%d X.%d %s\n",ramchain->height,ramchain->numblocks,ramchain->data->numblocks,ramchain->txidind,ramchain->unspentind,ramchain->spendind,ramchain->pkind,ramchain->externalind,bits256_str(str,ramchain->data->firsthash2));
    if ( ramchain->H.txidind != ramchain->H.data->numtxids || ramchain->H.unspentind != ramchain->H.data->numunspents || ramchain->H.spendind != ramchain->H.data->numspends )
    {
        printf("error creating PT ramchain: ramchain->txidind %d != %d ramchain->data->numtxids || ramchain->unspentind %d != %d ramchain->data->numunspents || ramchain->spendind %d != %d ramchain->data->numspends\n",ramchain->H.txidind,ramchain->H.data->numtxids,ramchain->H.unspentind,ramchain->H.data->numunspents,ramchain->H.spendind,ramchain->H.data->numspends);
    }
    else
    {
        if ( (err= iguana_ramchain_verify(coin,ramchain)) == 0 )
        {
            if ( (bp->fpos[bundlei]= iguana_ramchain_save(coin,RAMCHAIN_ARG,addr->ipbits,origtxdata->block.hash2,bundlei)) >= 0 )
            {
                bp->ipbits[bundlei] = addr->ipbits;
                ramchain->H.ROflag = 0;
                flag = 1;
                memset(&R,0,sizeof(R));
                if ( 0 && (mapchain= iguana_ramchain_map(coin,&R,0,addr->ipbits,origtxdata->block.hash2,bundlei,bp->fpos[bundlei],1)) != 0 )
                {
                    //printf("mapped Soffset.%ld\n",(long)mapchain->data->Soffset);
                    iguana_ramchain_link(&R,origtxdata->block.hash2,origtxdata->block.hash2,bp->hdrsi,bp->bundleheight+bundlei,bundlei,1,firsti,1);
                    if ( 0 ) // crashes unix
                    {
                        if ( (err= iguana_ramchain_cmp(ramchain,mapchain,0)) != 0 )
                            printf("error.%d comparing ramchains\n",err);
                        ptr = mapchain->fileptr; fsize = mapchain->filesize;
                        mapchain->fileptr = 0, mapchain->filesize = 0;
                        iguana_ramchain_free(mapchain,1);
                        memset(&R,0,sizeof(R));
                        R.H.data = (void *)((long)ptr + bp->fpos[bundlei]), R.filesize = fsize;
                        iguana_ramchain_link(&R,origtxdata->block.hash2,origtxdata->block.hash2,bp->hdrsi,bp->bundleheight+bundlei,bundlei,1,firsti,1);
                    }
                    if ( (err= iguana_ramchain_cmp(ramchain,&R,0)) != 0 )
                    {
                        bp->fpos[bundlei] = -1;
                        printf("error.%d comparing REMAP ramchains\n",err);
                    }
                    else if ( 1 )
                    {
                        iguana_ramchain_extras(&R,0);
                        if ( (err= iguana_ramchain_iterate(coin,0,&R)) != 0 )
                            printf("err.%d iterate ",err);
                        //printf("SUCCESS REMAP\n");
                        bp->numtxids += ramchain->H.data->numtxids;
                        bp->numunspents += ramchain->H.data->numunspents;
                        bp->numspends += ramchain->H.data->numspends;
                    }
                    iguana_ramchain_free(&R,1);
                }
                else
                {
                    bp->numtxids += ramchain->H.data->numtxids;
                    bp->numunspents += ramchain->H.data->numunspents;
                    bp->numspends += ramchain->H.data->numspends;
                }
            }
        } else printf("ramchain verification error.%d hdrsi.%d bundlei.%d\n",err,bp->hdrsi,bundlei);
    }
    ramchain->H.ROflag = 0;
    iguana_ramchain_free(ramchain,0);
    return(bp->fpos[bundlei]);
}

// two passes to check data size

void iguana_ramchain_disp(struct iguana_ramchain *ramchain)
{
    RAMCHAIN_DECLARE; int32_t j; uint32_t txidind,unspentind,spendind; struct iguana_txid *tx; char str[65];
    _iguana_ramchain_setptrs(RAMCHAIN_PTRS);
    if ( ramchain->H.data != 0 )
    {
        unspentind = spendind = ramchain->H.data->firsti;
        for (txidind=ramchain->H.data->firsti; txidind<ramchain->H.data->numtxids; txidind++)
        {
            tx = &T[txidind];
            for (j=0; j<tx->numvins; j++, spendind++)
                printf("%s/v%d ",bits256_str(str,S[spendind].prevhash2),S[spendind].prevout);
            for (j=0; j<tx->numvouts; j++,unspentind++)
            {
                init_hexbytes_noT(str,U[unspentind].rmd160,20);
                printf("(%.8f %s) ",dstr(U[unspentind].value),str);
            }
            printf("txid.[%d] %s (%d:%d %d:%d)\n",txidind,bits256_str(str,tx->txid),tx->firstvout,tx->numvouts,tx->firstvin,tx->numvins);
        }
    }
}

int32_t iguana_bundlefiles(struct iguana_info *coin,uint32_t *ipbits,void **ptrs,long *filesizes,struct iguana_bundle *bp)
{
    int32_t j,bundlei,num,hdrsi,checki; char fname[1024];
    for (bundlei=num=0; bundlei<bp->n; bundlei++)
    {
        if ( num > 0 )
        {
            for (j=0; j<num; j++)
                if ( ipbits[j] == bp->ipbits[bundlei] )
                    break;
        } else j = 0;
        if ( j == num )
        {
            ipbits[num] = bp->ipbits[bundlei];
            if ( (checki= iguana_peerfname(coin,&hdrsi,"tmp",fname,bp->ipbits[bundlei],bp->hashes[bundlei])) != bundlei || bundlei < 0 || bundlei >= coin->chain->bundlesize )
            {
                printf("iguana_ramchain_map.(%s) illegal hdrsi.%d bundlei.%d\n",fname,hdrsi,bundlei);
                return(0);
            }
            if ( (ptrs[num]= map_file(fname,&filesizes[num],0)) == 0 )
                return(0);
            num++;
        }
    }
    return(num);
}

void iguana_bundlemapfree(struct iguana_memspace *mem,uint32_t *ipbits,void **ptrs,long *filesizes,int32_t num,struct iguana_ramchain *R,int32_t n)
{
    int32_t j;
    for (j=0; j<num; j++)
        if ( ptrs[j] != 0 && filesizes[j] != 0 )
            munmap(ptrs[j],filesizes[j]);
    myfree(ptrs,n * sizeof(*ptrs));
    myfree(ipbits,n * sizeof(*ipbits));
    myfree(filesizes,n * sizeof(*filesizes));
    if ( R != 0 )
    {
        for (j=0; j<n; j++)
            iguana_ramchain_free(&R[j],1);
        myfree(R,n * sizeof(*R));
    }
    if ( mem != 0 )
        iguana_mempurge(mem);
}

// helper threads: NUM_HELPERS
int32_t iguana_bundlesaveHT(struct iguana_info *coin,struct iguana_memspace *mem,struct iguana_memspace *memB,struct iguana_bundle *bp,uint32_t starttime) // helper thread
{
    static int depth;
    RAMCHAIN_DESTDECLARE; void **ptrs,*ptr; long *filesizes,filesize; uint32_t *ipbits; char fname[1024];
    long allocsize; struct iguana_ramchain *R,*mapchain,*dest; uint32_t now = (uint32_t)time(NULL);
    int32_t j,num,numtxids,numunspents,numspends,numpkinds,numexternaltxids,hdrsi,bundlei,firsti= 1,retval = -1;
    R = mycalloc('s',bp->n,sizeof(*R));
    ptrs = mycalloc('w',bp->n,sizeof(*ptrs));
    ipbits = mycalloc('w',bp->n,sizeof(*ipbits));
    filesizes = mycalloc('f',bp->n,sizeof(*filesizes));
    if ( (num= iguana_bundlefiles(coin,ipbits,ptrs,filesizes,bp)) == 0 )
    {
        iguana_bundlemapfree(0,ipbits,ptrs,filesizes,num,R,bp->n);
        return(-1);
    }
    for (bundlei=numtxids=numunspents=numspends=0; bundlei<bp->n; bundlei++)
    {
        mapchain = &R[bundlei];
        for (j=0; j<num; j++)
            if ( ipbits[j] == bp->ipbits[bundlei] )
            {
                ptr = ptrs[j];
                filesize = filesizes[j];
                break;
            }
        if ( j == num )
        {
            printf("j.%d num.%d bundlei.%d\n",j,num,bundlei);
            break;
        }
        mapchain->fileptr = ptr;
        mapchain->filesize = filesize;
        mapchain->H.data = (void *)((long)ptr + bp->fpos[bundlei]);
        mapchain->H.ROflag = 1;
        if ( iguana_ramchain_size(mapchain) != mapchain->H.data->allocsize || bp->fpos[bundlei]+mapchain->H.data->allocsize > filesize )
        {
            printf("iguana_bundlesaveHT size mismatch %ld vs %ld vs filesize.%ld\n",(long)iguana_ramchain_size(mapchain),(long)mapchain->H.data->allocsize,(long)filesize);
            break;
        }
        else if ( memcmp(bp->hashes[bundlei].bytes,mapchain->H.data->firsthash2.bytes,sizeof(bits256)) != 0 )
        {
            char str[65],str2[65]; printf("iguana_bundlesaveHT hash2 mismatch %s vs %s\n",bits256_str(str,bp->hashes[bundlei]),bits256_str(str2,mapchain->H.data->firsthash2));
            break;
        }
        iguana_ramchain_link(&R[bundlei],bp->hashes[bundlei],bp->hashes[bundlei],bp->hdrsi,bp->bundleheight+bundlei,bundlei,1,firsti,1);
        numtxids += mapchain->H.data->numtxids;
        numunspents += mapchain->H.data->numunspents;
        numspends += mapchain->H.data->numspends;
    }
    if ( bundlei != bp->n )
    {
        iguana_bundlemapfree(0,ipbits,ptrs,filesizes,num,R,bp->n);
        printf("error mapping hdrsi.%d bundlei.%d\n",bp->hdrsi,bundlei);
        return(-1);
    }
    numpkinds = numunspents;
    numexternaltxids = numspends;
    dest = &bp->ramchain;
    printf("E.%d depth.%d start bundle ramchain %d at %u started.%u lag.%d\n",coin->numemitted,depth,bp->bundleheight,now,starttime,now-starttime);
    depth++;
    allocsize = sizeof(*dest) +
                (numtxids * sizeof(struct iguana_txid)) +
                (numunspents * (sizeof(struct iguana_unspent) + sizeof(struct iguana_Uextra))) +
                (numspends * sizeof(struct iguana_spend)) +
                (numpkinds * (sizeof(struct iguana_pkhash) + sizeof(struct iguana_pkextra) + sizeof(struct iguana_account))) +
                (numexternaltxids * sizeof(bits256));
    iguana_meminit(mem,"ramchain",0,allocsize + 4096,0);
    mem->alignflag = sizeof(uint32_t);
    if ( iguana_ramchain_init(dest,mem,0,1,numtxids,numunspents,numspends,0,0,1) == 0 )
    {
        iguana_bundlemapfree(mem,ipbits,ptrs,filesizes,num,R,bp->n);
        return(-1);
    }
    iguana_ramchain_link(dest,bp->hashes[0],bp->hashes[bp->n-1],bp->hdrsi,bp->bundleheight,0,bp->n,firsti,0);
    _iguana_ramchain_setptrs(RAMCHAIN_DESTPTRS);
    iguana_ramchain_extras(dest,0);
    iguana_ramchain_setsize(dest);
    if ( bundlei == bp->n )
    {
        if ( iguana_ramchain_save(coin,RAMCHAIN_DESTARG,0,bp->hashes[0],0) < 0 )
            printf("ERROR saving ramchain hdrsi.%d\n",bp->hdrsi);
        else
        {
            char str[65]; printf("depth.%d ht.%d %s saved lag.%d elapsed.%ld\n",depth,bp->bundleheight,bits256_str(str,bp->hashes[0]),now-starttime,time(NULL)-now);
            retval = 0;
        }
    }
    printf("free dest hdrs.%d retval.%d\n",bp->hdrsi,retval);
    iguana_ramchain_free(dest,1);
    printf("free iguana_bundlemapfree hdrs.%d retval.%d\n",bp->hdrsi,retval);
    iguana_bundlemapfree(mem,ipbits,ptrs,filesizes,num,R,bp->n);
    depth--;
    if ( retval == 0 )
    {
        printf("delete %d files hdrs.%d retval.%d\n",num,bp->hdrsi,retval);
        for (j=0; j<num; j++)
            if ( 0 && iguana_peerfname(coin,&hdrsi,"tmp",fname,ipbits[j],bp->hashes[0]) == 0 )
                iguana_removefile(fname,0), coin->peers.numfiles--;
    }
    printf("done hdrs.%d retval.%d\n",bp->hdrsi,retval);
    return(retval);
}

struct iguana_ramchain *iguana_ramchainmergeHT(struct iguana_info *coin,struct iguana_memspace *mem,struct iguana_ramchain *ramchains[],int32_t n,struct iguana_bundle *bp)
{
/*    uint32_t numtxids,numunspents,numspends,numpkinds,numexternaltxids,i,j,k; uint64_t allocsize = 0;
    struct iguana_txid *tx;  struct iguana_account *acct; struct iguana_ramchain *ramchain,*item;
    struct iguana_pkhash *p,oldP; struct iguana_unspent *u; struct iguana_kvitem *ptr;
    bits256 txid; uint32_t txidind,unspentind,spendind,pkind,numblocks; struct iguana_spend *s;
    numtxids = numunspents = numspends = numpkinds = 1;
    numexternaltxids = 1;
    numblocks = 0;
    for (i=0; i<n; i++)
    {
        if ( (item= ramchains[i]) == 0 )
        {
            printf("iguana_ramchaininit null hdrsi.%d txdatas[%d]\n",bp->ramchain.hdrsi,i);
            return(0);
        }
        numtxids += item->numtxids, numunspents += item->numunspents, numspends += item->numspends;
        numpkinds += item->numpkinds, numexternaltxids += item->numexternaltxids;
        numblocks += item->numblocks;
    }
    allocsize = sizeof(*ramchain) +
                (numtxids * sizeof(*ramchain->T)) +
                (numunspents * (sizeof(*ramchain->U) + sizeof(*ramchain->Uextras))) +
                (numspends * sizeof(*ramchain->S)) +
                (numpkinds * (sizeof(*ramchain->P) + sizeof(*ramchain->pkextras) + sizeof(*ramchain->accounts))) +
                (numexternaltxids * sizeof(*ramchain->externalT));
    
    iguana_meminit(mem,"ramchain",0,allocsize,0);
    mem->alignflag = sizeof(uint32_t);
    ramchain= &bp->ramchain; //iguana_memalloc(mem,sizeof(*ramchain),1)) == 0 )
    ramchain->numblocks = numblocks;
    ramchain->numtxids = numtxids, ramchain->numunspents = numunspents;
    ramchain->numspends = numspends, ramchain->numpkinds = numpkinds;
    ramchain->numexternaltxids = numexternaltxids;
    ramchain->hdrsi = bp->ramchain.hdrsi, ramchain->bundleheight = bp->ramchain.bundleheight, ramchain->numblocks = n;
    ramchain->prevbundlehash2 = bp->prevbundlehash2, ramchain->nextbundlehash2 = bp->nextbundlehash2;
    ramchain->hash2 = ramchains[0]->hash2;
    ramchain->prevhash2 = ramchains[0]->prevhash2, ramchain->lasthash2 = ramchains[n-1]->hash2;
    ramchain->T = iguana_memalloc(mem,sizeof(*ramchain->T) * ramchain->numtxids,0);
    ramchain->U = iguana_memalloc(mem,sizeof(*ramchain->U) * ramchain->numunspents,0);
    if ( ramchain->numspends > 0 )
        ramchain->S = iguana_memalloc(mem,sizeof(*ramchain->S) * ramchain->numspends,0);
    ramchain->Uextras = iguana_memalloc(mem,sizeof(*ramchain->Uextras) * ramchain->numunspents,1);
    ramchain->P = iguana_memalloc(mem,sizeof(*ramchain->P) * ramchain->numpkinds,1);
    ramchain->pkextras = iguana_memalloc(mem,sizeof(*ramchain->pkextras) * ramchain->numpkinds,1);
    ramchain->accounts = iguana_memalloc(mem,sizeof(*ramchain->accounts) * ramchain->numpkinds,1);
    if ( ramchain->numexternaltxids > 0 )
        ramchain->externalT = iguana_memalloc(mem,ramchain->numexternaltxids * sizeof(*ramchain->externalT),1);
    if ( mem->used != allocsize )
    {
        printf("error allocating ramchain %ld != %ld\n",(long)mem->used,(long)allocsize);
        iguana_ramchainfree(coin,mem,ramchain);
        return(0);
    }
    ramchain->allocsize = allocsize;
    ramchain->firsti = 1;
    //printf("Allocated %s for bp %d\n",mbstr(str,allocsize),bp->ramchain.bundleheight);
    txidind = unspentind = numtxids = spendind = numunspents = numspends = numpkinds = ramchain->firsti;
    numexternaltxids = 0;
    for (i=0; i<n; i++)
    {
        if ( (item= ramchains[i]) != 0 )
        {
            // iguana_txid { bits256 txid; uint32_t txidind,firstvout,firstvin; uint16_t numvouts,numvins;}
            for (j=item->firsti; j<item->numtxids; j++,txidind++)
            {
                tx = &ramchain->T[txidind];
                *tx = item->T[j];
                tx->txidind = txidind;
                if ( (ptr= iguana_hashfind(ramchain->txids,tx->txid.bytes,sizeof(tx->txid))) != 0 )
                {
                    printf("unexpected duplicate txid[%d]\n",txidind);
                    iguana_ramchainfree(coin,mem,ramchain);
                    return(0);
                }
                iguana_hashsetHT(ramchain->txids,0,tx->txid.bytes,sizeof(bits256),txidind);
                tx->firstvout = unspentind;
                for (k=item->firsti; k<tx->numvouts; k++,unspentind++)
                {
                    u = &ramchain->U[unspentind];
                    *u = item->U[k];
                    u->txidind = txidind;
                    oldP = item->P[item->U[k].pkind];
                    if ( (ptr= iguana_hashfind(ramchain->pkhashes,oldP.rmd160,sizeof(oldP.rmd160))) == 0 )
                    {
                        pkind = numpkinds++;
                        p = &ramchain->P[pkind];
                        *p = oldP;
                        p->firstunspentind = unspentind;
                        if ( (ptr= iguana_hashsetHT(ramchain->pkhashes,0,p->rmd160,sizeof(p->rmd160),numpkinds)) == 0 )
                        {
                            iguana_ramchainfree(coin,mem,ramchain);
                            printf("fatal error adding pkhash\n");
                            return(0);
                        }
                        //printf("pkind.%d: %p %016lx <- %016lx\n",pkind,p,*(long *)p->rmd160,*(long *)oldP.rmd160);
                    } else pkind = ptr->hh.itemind;
                    u->pkind = pkind;
                    acct = &ramchain->accounts[pkind];
                    u->prevunspentind = acct->lastunspentind;
                    acct->lastunspentind = unspentind;
                    acct->balance += u->value;
                }
                tx->firstvin = spendind;
                spendind += tx->numvins;
            }
            numtxids += item->numtxids, numunspents += item->numunspents;
        }
    }
    txidind = spendind = ramchain->firsti;
    for (i=0; i<n; i++)
    {
        if ( (item= ramchains[i]) != 0 )
        {
            for (j=item->firsti; j<item->numtxids; j++,txidind++)
            {
                tx = &ramchain->T[j];
                for (k=item->firsti; k<tx->numvins; k++)
                {
                    //printf("item.%p [%d] X.%p i.%d j.%d k.%d txidind.%d/%d spendind.%d/%d s->txidind.%d/v%d\n",item,item->numexternaltxids,item->externalT,i,j,k,txidind,ramchain->numtxids,spendind,ramchain->numspends,item->S[k].spendtxidind,item->S[k].vout);
                    if ( iguana_ramchaintxid(coin,&txid,item,&item->S[k]) < 0 )
                    {
                        printf("i.%d j.%d k.%d error getting txid firsti.%d X.%d vout.%d spend.%d/%d numX.%d numT.%d\n",i,j,k,item->firsti,item->S[k].external,item->S[k].vout,item->S[k].spendtxidind,item->numspends,item->numexternaltxids,item->numtxids);
                        //iguana_ramchainfree(coin,mem,ramchain);
                        //return(0);
                    }
                    s = &ramchain->S[spendind];
                    *s = item->S[k];
                    if ( s->vout == 0xffff )
                    {
                        // mining output
                    }
                    else if ( (ptr= iguana_hashfind(ramchain->txids,txid.bytes,sizeof(txid))) != 0 )
                    {
                        if ( (s->spendtxidind= ptr->hh.itemind) >= ramchain->numtxids )
                        {
                            s->external = 1;
                            s->spendtxidind -= ramchain->numtxids;
                        }
                        else if ( s->spendtxidind >= item->firsti && s->spendtxidind < item->numtxids )
                        {
                            s->external = 0;
                            unspentind = (ramchain->T[s->spendtxidind].firstvout + s->vout);
                            u = &ramchain->U[unspentind];
                            p = &ramchain->P[u->pkind];
                            if ( ramchain->pkextras[u->pkind].firstspendind == 0 )
                                ramchain->pkextras[u->pkind].firstspendind = spendind;
                            acct = &ramchain->accounts[u->pkind];
                            s->prevspendind = acct->lastspendind;
                            acct->lastspendind = spendind;
                            if ( ramchain->Uextras[unspentind].spendind != 0 )
                            {
                                printf("double spend u.%d has spendind.%d when s.%d refers to it\n",unspentind,ramchain->Uextras[unspentind].spendind,spendind);
                                iguana_ramchainfree(coin,mem,ramchain);
                                return(0);
                            }
                            ramchain->Uextras[unspentind].spendind = spendind;
                        }
                        spendind++;
                    }
                    else if ( numexternaltxids < ramchain->numexternaltxids )
                    {
                        s->external = 1;
                        ramchain->externalT[numexternaltxids] = txid;
                        iguana_hashsetHT(ramchain->txids,0,ramchain->externalT[numexternaltxids].bytes,sizeof(ramchain->externalT[numexternaltxids]),ramchain->numtxids + numexternaltxids);
                        s->spendtxidind = numexternaltxids++;
                        spendind++;
                    }
                    else printf("numexternaltxids.%d >= ramchain numexternaltxids.%d\n",numexternaltxids,ramchain->numexternaltxids);
                }
            }
            // iguana_unspent { uint64_t value; uint32_t txidind,pkind,prevunspentind; } iguana_Uextra { uint32_t spendind; }
            // iguana_pkhash { uint8_t rmd160[20]; uint32_t firstunspentind,flags; } iguana_pkextra { uint32_t firstspendind; }
            // iguana_account { uint64_t balance; uint32_t lastunspentind,lastspendind; }
            // iguana_spend { uint32_t unspentind,prevspendind:31,diffsequence:1; }
            numspends += item->numspends;
        }
    }
    //for (i=0; i<numpkinds; i++)
    //    printf("have pkind.%d: %p %016lx\n",i,&ramchain->P[i],*(long *)ramchain->P[i].rmd160);
    //printf("numpkinds.%d\n",numpkinds);
    if ( 0 )
    {
        memcpy(&ramchain->P[numpkinds],ramchain->pkextras,sizeof(*ramchain->pkextras) * numpkinds);
        ramchain->pkextras = (void *)&ramchain->P[numpkinds];
        memcpy(&ramchain->pkextras[numpkinds],ramchain->accounts,sizeof(*ramchain->accounts) * numpkinds);
        ramchain->accounts = (void *)&ramchain->pkextras[numpkinds];
        memcpy(&ramchain->accounts[numpkinds],ramchain->externalT,sizeof(*ramchain->externalT) * numexternaltxids);
        ramchain->externalT = (void *)&ramchain->accounts[numpkinds];
    }
    ramchain->allocsize -= ((ramchain->numpkinds - numpkinds) * (sizeof(*ramchain->P) + sizeof(*ramchain->pkextras) + sizeof(*ramchain->accounts)));
    ramchain->allocsize -= ((ramchain->numexternaltxids - numexternaltxids) * sizeof(*ramchain->externalT));
    ramchain->numpkinds = numpkinds;
    ramchain->numexternaltxids = numexternaltxids;*/
    /*vupdate_sha256(ramchain->lhashes[IGUANA_LHASH_UNSPENT].bytes,&ramchain->states[IGUANA_LHASH_UNSPENT],(void *)ramchain->U,sizeof(*ramchain->U)*ramchain->numunspents);
    vupdate_sha256(ramchain->lhashes[IGUANA_LHASH_ACCOUNTS].bytes,&ramchain->states[IGUANA_LHASH_ACCOUNTS],(void *)acct,sizeof(*acct));
    vupdate_sha256(ramchain->lhashes[IGUANA_LHASH_SPENDS].bytes,&ramchain->states[IGUANA_LHASH_SPENDS],(void *)ramchain->S,sizeof(*ramchain->S)*);
    vupdate_sha256(ramchain->lhashes[IGUANA_LHASH_TXIDS].bytes,&ramchain->states[IGUANA_LHASH_TXIDS],(void *)tx,sizeof(*tx));*/
    /*mem->used = (long)ramchain->allocsize;
    printf("B.%d T.%d U.%d S.%d P.%d combined ramchain size.%ld\n",ramchain->numblocks,ramchain->numtxids,ramchain->numunspents,ramchain->numspends,ramchain->numpkinds,(long)ramchain->allocsize);
    return(ramchain);*/
    return(0);
}


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

#define iguana_hashfind(ramchain,selector,key) iguana_hashsetPT(ramchain,selector,key,-1)

struct iguana_kvitem *iguana_hashsetPT(struct iguana_ramchain *ramchain,int32_t selector,void *key,int32_t itemind)
{
    struct iguana_kvitem *ptr = 0; int32_t allocsize,keylen;
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
    if ( ptr == 0 && itemind != (uint32_t)-1 )
    {
        if ( ramchain->hashmem != 0 )
            ptr = iguana_memalloc(ramchain->hashmem,allocsize,1);
        else ptr = mycalloc('p',1,allocsize);//, ptr->allocsize = allocsize;
        if ( ptr == 0 )
            printf("fatal alloc error in hashset\n"), exit(-1);
        //printf("%s ptr.%p allocsize.%d key.%p keylen.%d itemind.%d\n",addr->ipaddr,ptr,allocsize,key,keylen,itemind);
        ptr->hh.itemind = itemind;
        if ( selector == 'T' )
            HASH_ADD_KEYPTR(hh,ramchain->txids,key,keylen,ptr);
        else HASH_ADD_KEYPTR(hh,ramchain->pkhashes,key,keylen,ptr);
    }
    if ( ptr != 0 )
    {
        struct iguana_kvitem *tmp;
        HASH_FIND(hh,((selector == 'T') ? ramchain->txids : ramchain->pkhashes),key,keylen,tmp);
        char str[65];
        init_hexbytes_noT(str,key,keylen);
        if ( tmp != ptr )
            printf("%s search error %p != %p\n",str,ptr,tmp), getchar();
        // else printf("added.(%s) height.%d %p\n",str,itemind,ptr);
    }
    return(ptr);
}

int32_t iguana_peerfname(struct iguana_info *coin,int32_t *hdrsip,char *fname,uint32_t ipbits,bits256 hash2)
{
    struct iguana_bundle *bp = 0; int32_t bundlei = -2; char str[65];
    *hdrsip = -1;
    if ( ipbits == 0 )
        printf("illegal ipbits.%d\n",ipbits), getchar();
    if ( (bp= iguana_bundlefind(coin,&bp,&bundlei,hash2)) != 0 )
        hash2 = bp->hashes[0], *hdrsip = bp->hdrsi;
    sprintf(fname,"tmp/%s/%s.peer%08x",coin->symbol,bits256_str(str,hash2),ipbits);
    return(bundlei);
}

int32_t iguana_peerfile_exists(struct iguana_info *coin,struct iguana_peer *addr,char *fname,bits256 hash2)
{
    FILE *fp; int32_t bundlei,hdrsi;
    if ( (bundlei= iguana_peerfname(coin,&hdrsi,fname,addr->ipbits,hash2)) >= 0 )
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

uint32_t iguana_ramchain_addtxid(struct iguana_info *coin,RAMCHAIN_FUNC,bits256 txid,int32_t numvouts,int32_t numvins)
{
    uint32_t txidind; struct iguana_txid *t; struct iguana_kvitem *ptr;
    txidind = ramchain->txidind;
    t = &T[txidind];
    if ( ramchain->ROflag != 0 )
    {
        if ( t->txidind != txidind || memcmp(t->txid.bytes,txid.bytes,sizeof(bits256)) != 0 || t->numvouts != numvouts || t->numvins != numvins || t->firstvout != ramchain->unspentind || t->firstvin != ramchain->spendind )
        {
            printf("iguana_ramchain_addtxid: addtxid mismatch (%d %d %d %d %d) vs. (%d %d %d %d %d)\n",t->txidind,t->numvouts,t->numvins,t->firstvout,t->firstvin,txidind,numvouts,numvins,ramchain->unspentind,ramchain->spendind);
            getchar();
            return(0);
        }
    }
    else
    {
        t->txidind = txidind, t->txid = txid, t->numvouts = numvouts, t->numvins = numvins;
        t->firstvout = ramchain->unspentind, t->firstvin = ramchain->spendind;
        //if ( txidind <= 2 )
        //    printf("%p TXID.[%d] firstvout.%d/%d firstvin.%d/%d\n",t,txidind,ramchain->unspentind,numvouts,ramchain->spendind,numvins);
    }
    if ( ramchain->numblocks > 1 && (ptr= iguana_hashsetPT(ramchain,'T',t->txid.bytes,txidind)) == 0 )
    {
        printf("iguana_ramchain_addtxid error adding txidind\n");
        return(0);
    }
    return(txidind);
}

uint32_t iguana_ramchain_addpkhash(struct iguana_info *coin,RAMCHAIN_FUNC,uint8_t rmd160[20],int32_t flags,uint32_t unspentind)
{
    struct iguana_kvitem *ptr; uint32_t pkind = 0;
    if ( ramchain->numblocks > 1 && (ptr= iguana_hashfind(ramchain,'P',rmd160)) == 0 )
    {
        pkind = ramchain->pkind++;
        if ( ramchain->ROflag != 0 )
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
    unspentind = ramchain->unspentind++;
    u = &U[unspentind];
    if ( scriptlen == -20 )
        memcpy(rmd160,script,20);
    else iguana_calcrmd160(coin,rmd160,script,scriptlen,txid);
    if ( ramchain->ROflag != 0 )
    {
        //printf("%p U[%d] txidind.%d pkind.%d\n",u,unspentind,ramchain->txidind,pkind);
        if ( u->txidind != ramchain->txidind || u->value != value || memcmp(u->rmd160,rmd160,sizeof(rmd160)) != 0 )
        {
            printf("iguana_ramchain_addunspent: mismatched values.(%.8f %d) vs (%.8f %d)\n",dstr(u->value),u->txidind,dstr(value),ramchain->txidind);
            return(0);
        }
    }
    else
    {
        u->value = value;
        u->txidind = ramchain->txidind;
        memcpy(u->rmd160,rmd160,sizeof(rmd160));
    }
    return(unspentind);
}

uint32_t iguana_ramchain_addunspent(struct iguana_info *coin,RAMCHAIN_FUNC,uint64_t value,uint8_t *rmd160)
{
    //struct iguana_unspent { uint64_t value; uint32_t txidind,pkind,prevunspentind; } __attribute__((packed));
    uint32_t unspentind; struct iguana_unspent *u; struct iguana_kvitem *ptr; int32_t pkind;
    unspentind = ramchain->unspentind++;
    u = &Ux[unspentind];
    if ( (ptr= iguana_hashfind(ramchain,'P',rmd160)) == 0 )
        pkind = iguana_ramchain_addpkhash(coin,RAMCHAIN_ARG,rmd160,0,unspentind);
    else pkind = ptr->hh.itemind;
    if ( pkind == 0 )
        return(0);
    if ( ramchain->ROflag != 0 )
    {
        //printf("%p U[%d] txidind.%d pkind.%d\n",u,unspentind,ramchain->txidind,pkind);
        if ( u->value != value || u->pkind != pkind || u->value != value || u->txidind != ramchain->txidind || (pkind != 0 && u->prevunspentind != A[pkind].lastunspentind) )
        {
            printf("iguana_ramchain_addunspent: mismatched values.(%d %.8f %d %d) vs (%d %.8f %d %d) %p\n",u->pkind,dstr(u->value),u->txidind,u->prevunspentind,pkind,dstr(value),ramchain->txidind,A[pkind].lastunspentind,&A[pkind]);
            return(0);
        }
    }
    else
    {
        u->value = value;
        u->txidind = ramchain->txidind, u->pkind = pkind;
        u->prevunspentind = A[pkind].lastunspentind;
    }
    //printf("%p A[%d] last <- U%d\n",&A[pkind],pkind,unspentind);
    A[pkind].balance += value;
    A[pkind].lastunspentind = unspentind;
    return(unspentind);
}

uint32_t iguana_ramchain_addspend256(struct iguana_info *coin,RAMCHAIN_FUNC,bits256 prev_hash,int32_t prev_vout,uint8_t *script,int32_t scriptlen,uint32_t sequence,int32_t hdrsi)
{
    struct iguana_spend256 *s; uint32_t spendind;
    spendind = ramchain->spendind++;
    s = &S[spendind];
    if ( ramchain->ROflag != 0 )
    {
        if ( (s->diffsequence == 0 && sequence != 0xffffffff) || (s->diffsequence != 0 && sequence == 0xffffffff) || memcmp(s->prevhash2.bytes,prev_hash.bytes,sizeof(bits256)) != 0 || s->prevout != prev_vout )
        {
            printf("ramchain_addspend RO value mismatch (%d %d) vs (%d %d)\n",s->prevout,s->hdrsi,prev_vout,hdrsi);
            return(0);
        }
    }
    else
    {
        if ( sequence != 0xffffffff )
            s->diffsequence = 1;
        s->prevhash2 = prev_hash, s->prevout = prev_vout;
        s->hdrsi = hdrsi;
    }
    return(spendind);
}

//struct iguana_spend { uint32_t prevspendind,spendtxidind; uint16_t vout,hdrsi:14,external:1,diffsequence:1; } __attribute__((packed)); // dont need nextspend

int32_t iguana_ramchain_txid(struct iguana_info *coin,RAMCHAIN_FUNC,bits256 *txidp,struct iguana_spend *s)
{
    int32_t ind,external;
    memset(txidp,0,sizeof(*txidp));
    //printf("s.%p ramchaintxid vout.%x spendtxidind.%d numexternals.%d isext.%d numspendinds.%d\n",s,s->vout,s->spendtxidind,ramchain->numexternaltxids,s->external,ramchain->numspends);
    if ( s->prevout == 0xffff )
        return(-1);
    ind = s->spendtxidind;
    external = (ind >> 31) & 1;
    ind &= ~(1 << 31);
    if ( s->external != 0 && s->external == external && ind < ramchain->data->numexternaltxids )
    {
        //printf("ind.%d externalind.%d X[%d]\n",ind,ramchain->externalind,ramchain->data->numexternaltxids);
        *txidp = X[ind];
        return(s->prevout);
    }
    else if ( s->external == 0 && s->external == external && ind < ramchain->txidind )
    {
        *txidp = T[ind].txid;
        return(s->prevout);
    }
    return(-2);
}

uint32_t iguana_ramchain_addspend(struct iguana_info *coin,RAMCHAIN_FUNC,bits256 prev_hash,int32_t prev_vout,uint32_t sequence,int32_t hdrsi)
{
    struct iguana_spend *s; struct iguana_kvitem *ptr; bits256 txid;
    uint32_t spendind,unspentind,txidind,pkind,external; uint64_t value = 0;
    spendind = ramchain->spendind++;
    s = &Sx[spendind];
    pkind = unspentind = 0;
    if ( (ptr= iguana_hashfind(ramchain,'T',prev_hash.bytes)) == 0 )
    {
        external = 1;
        txidind = ramchain->externalind++;
        //char str[65]; printf("X[%d] <- %s\n",txidind,bits256_str(str,prev_hash));
        if ( ramchain->ROflag != 0 )
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
        unspentind = T[txidind].firstvout + prev_vout;
        value = U[unspentind].value;
        if ( (pkind= Ux[unspentind].pkind) >= ramchain->data->numpkinds )
        {
            printf("spendind.%d -> unspendind.%d %.8f -> pkind.%d\n",spendind,unspentind,dstr(value),pkind);
            return(0);
        }
    }
    if ( ramchain->ROflag != 0 )
    {
        iguana_ramchain_txid(coin,RAMCHAIN_ARG,&txid,s);
        if ( (s->diffsequence == 0 && sequence != 0xffffffff) || (s->diffsequence != 0 && sequence == 0xffffffff) || memcmp(txid.bytes,prev_hash.bytes,sizeof(bits256)) != 0 || s->prevout != prev_vout )
        {
            printf("ramchain_addspend RO value mismatch (%d %d) vs (%d %d)\n",s->prevout,s->hdrsi,prev_vout,hdrsi);
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
        s->hdrsi = hdrsi;
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
    *T = (void *)((long)ramchain->data + (long)ramchain->data->Toffset);
    *U = (void *)((long)ramchain->data + (long)ramchain->data->Uoffset);
    *S = (void *)((long)ramchain->data + (long)ramchain->data->Soffset);
    if ( ramchain->numblocks > 1 )
    {
        *P = (void *)((long)ramchain->data + (long)ramchain->data->Poffset);
        *X = (void *)((long)ramchain->data + (long)ramchain->data->Xoffset);
        ramchain->roU2 = (void *)((long)ramchain->data + (long)ramchain->data->U2offset);
        ramchain->roP2 = (void *)((long)ramchain->data + (long)ramchain->data->P2offset);
        ramchain->roA = (void *)((long)ramchain->data + (long)ramchain->data->Aoffset);
        if ( (*U2= ramchain->U2) == 0 )
            *U2 = ramchain->U2 = ramchain->roU2;
        if ( (*P2= ramchain->P2) == 0 )
            *P2 = ramchain->P2 = ramchain->roP2;
        if ( (*A= ramchain->A) == 0 )
            *A = ramchain->A = ramchain->roA;
    }
}

int64_t iguana_ramchain_init(struct iguana_ramchain *ramchain,struct iguana_memspace *mem,struct iguana_memspace *hashmem,int32_t firsti,int32_t numtxids,int32_t numunspents,int32_t numspends,int32_t numpkinds,int32_t numexternaltxids)
{
    int64_t offset = 0;
    if ( mem == 0 )
        return(0);
    memset(ramchain,0,sizeof(*ramchain));
    if ( (ramchain->hashmem= hashmem) != 0 )
        iguana_memreset(hashmem);
    ramchain->data = mem->ptr, offset += sizeof(struct iguana_ramchaindata);
    if ( (ramchain->data->firsti= firsti) != 0 )
    {
        numtxids++, numunspents++, numspends++;
        if ( numpkinds != 0 )
            numpkinds++;
    }
    ramchain->data->Toffset = offset, offset += (sizeof(struct iguana_txid) * numtxids);
    ramchain->data->Uoffset = offset, offset += (sizeof(struct iguana_unspent20) * numunspents);
    ramchain->data->Soffset = offset, offset += (sizeof(struct iguana_spend256) * numspends);
    if ( ramchain->numblocks > 1 )
    {
        ramchain->data->U2offset = offset, offset += (sizeof(struct iguana_Uextra) * numunspents);
        if ( numexternaltxids == 0 )
            numexternaltxids = numspends;
        if ( numpkinds == 0 )
            numpkinds = numunspents;
        ramchain->data->Poffset = offset, offset += (sizeof(struct iguana_pkhash) * numpkinds);
        ramchain->data->P2offset = offset, offset += (sizeof(struct iguana_pkextra) * numpkinds);
        ramchain->data->Aoffset = offset, offset += (sizeof(struct iguana_account) * numpkinds);
        ramchain->data->Xoffset = offset, offset += (sizeof(bits256) * numexternaltxids);
    }
    if ( offset < mem->totalsize )
        iguana_memreset(mem);
    else
    {
        iguana_mempurge(mem);
        printf("NEED to realloc for %llu\n",(long long)offset);
        iguana_meminit(mem,"ramchain",0,offset,0);
    }
    ramchain->data->numtxids = numtxids;
    ramchain->data->numunspents = numunspents;
    ramchain->data->numspends = numspends;
    ramchain->data->numpkinds = numpkinds;
    ramchain->data->numexternaltxids = numexternaltxids;
    //printf("init.(%d %d %d %d %d)\n",numtxids,numunspents,numspends,numpkinds,numexternaltxids);
    return(offset);
}

int64_t iguana_ramchain_size(struct iguana_ramchain *ramchain)
{
    struct iguana_ramchaindata *rdata; int64_t offset = sizeof(struct iguana_ramchaindata);
    if ( (rdata= ramchain->data) != 0 )
    {
        offset += (sizeof(struct iguana_txid) * rdata->numtxids);
        offset += (sizeof(struct iguana_unspent20) * rdata->numunspents);
        offset += (sizeof(struct iguana_spend256) * rdata->numspends);
        if ( ramchain->numblocks > 1 )
        {
            offset += (sizeof(struct iguana_Uextra) * rdata->numunspents);
            offset += (sizeof(struct iguana_pkhash) * rdata->numpkinds);
            offset += (sizeof(struct iguana_pkextra) * rdata->numpkinds);
            offset += (sizeof(struct iguana_account) * rdata->numpkinds);
            offset += (sizeof(bits256) * rdata->numexternaltxids);
        }
    }
    return(offset);
}

long iguana_ramchain_save(struct iguana_info *coin,RAMCHAIN_FUNC,uint32_t ipbits,bits256 hash2,int32_t bundlei)
{
    struct iguana_ramchaindata *rdata,tmp;
    char fname[1024]; long fpos = -1; int32_t hdrsi,checki; int64_t offset; FILE *fp;
    if ( (rdata= ramchain->data) == 0 )
        return(-1);
    if ( (checki= iguana_peerfname(coin,&hdrsi,fname,ipbits,hash2)) != bundlei || bundlei < 0 || bundlei >= coin->chain->bundlesize )
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
        ramchain->data->Toffset = offset, offset += (sizeof(struct iguana_txid) * rdata->numtxids);
        ramchain->data->Uoffset = offset, offset += (sizeof(struct iguana_unspent20) * rdata->numunspents);
        ramchain->data->Soffset = offset, offset += (sizeof(struct iguana_spend256) * rdata->numspends);
        if ( rdata->numblocks > 1 )
        {
            ramchain->data->U2offset = offset, offset += (sizeof(struct iguana_Uextra) * rdata->numunspents);
            ramchain->data->Poffset = offset, offset += (sizeof(struct iguana_pkhash) * rdata->numpkinds);
            ramchain->data->P2offset = offset, offset += (sizeof(struct iguana_pkextra) * rdata->numpkinds);
            ramchain->data->Aoffset = offset, offset += (sizeof(struct iguana_account) * rdata->numpkinds);
            ramchain->data->Xoffset = offset, offset += (sizeof(bits256) * rdata->numexternaltxids);
        }
        rdata->allocsize = offset;
        fwrite(rdata,1,sizeof(*rdata),fp);
        *rdata = tmp;
        fwrite(T,sizeof(struct iguana_txid),rdata->numtxids,fp);
        fwrite(U,sizeof(struct iguana_unspent20),rdata->numunspents,fp);
        fwrite(S,sizeof(struct iguana_spend256),rdata->numspends,fp);
        //printf("fwrite P[%d] (%x %x) (%x %x)\n",(int32_t)ramchain->data->Poffset,P[1].firstunspentind,P[1].flags,P[2].firstunspentind,P[2].flags);
        if ( ramchain->numblocks > 1 )
        {
            fwrite(P,sizeof(struct iguana_pkhash),rdata->numpkinds,fp);
            fwrite(U2,sizeof(struct iguana_Uextra),rdata->numunspents,fp);
            fwrite(P2,sizeof(struct iguana_pkextra),rdata->numpkinds,fp);
            fwrite(A,sizeof(struct iguana_account),rdata->numpkinds,fp);
            fwrite(X,sizeof(bits256),rdata->numexternaltxids,fp);
            printf("iguana_ramchain_save:  (%ld - %ld) diff.%ld vs %ld [%ld]\n",ftell(fp),(long)fpos,(long)(ftell(fp) - fpos),(long)rdata->allocsize,(long)(ftell(fp) - fpos) - (long)rdata->allocsize);
        }
        if ( (ftell(fp) - fpos) != ramchain->data->allocsize )
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
    if ( (rdata= ramchain->data) == 0 )
        return(-100);
    _iguana_ramchain_setptrs(RAMCHAIN_PTRS);
    ramchain->pkind = ramchain->unspentind = ramchain->spendind = rdata->firsti;
    ramchain->externalind = 0;
    for (ramchain->txidind=rdata->firsti; ramchain->txidind<rdata->numtxids; ramchain->txidind++)
    {
        t = &T[ramchain->txidind];
        if ( t->txidind != ramchain->txidind )
        {
            printf("firsti.%d  t->txidind.%d != txidind.%d\n",rdata->firsti,t->txidind,ramchain->txidind);
            return(-1);
        }
        if ( t->firstvout != ramchain->unspentind )
        {
            printf("%p txidind.%d firstvout.%d != unspentind.%d\n",t,ramchain->txidind,t->firstvout,ramchain->unspentind);
            getchar();
            return(-4);
        }
        if ( t->firstvin != ramchain->spendind )
        {
            printf("t[%d] firstvin.%d vs spendind.%d\n",t->txidind,t->firstvin,ramchain->spendind);
            return(-5);
        }
        if ( ramchain->numblocks > 1 )
        {
            if ( (ptr= iguana_hashfind(ramchain,'T',t->txid.bytes)) == 0 )
                return(-2);
            if ( ptr->hh.itemind != ramchain->txidind )
                return(-3);
            for (k=0; k<t->numvouts; k++,ramchain->unspentind++)
            {
                u = &Ux[ramchain->unspentind];
                if ( u->txidind != ramchain->txidind )
                {
                    printf(" k.%d %p U.%d u->txidind.%x != txidind.%d\n",k,u,ramchain->unspentind,u->txidind,ramchain->txidind);
                    return(-6);
                }
                if ( (pkind= u->pkind) < 0 || pkind >= rdata->numpkinds )
                {
                    printf("k.%d unspentind.%d pkind.%d numpkinds.%d\n",k,ramchain->unspentind,pkind,rdata->numpkinds);
                    return(-7);
                }
                p = &P[pkind];
                if ( (ptr= iguana_hashfind(ramchain,'P',p->rmd160)) == 0 )
                    return(-8);
                if ( ptr->hh.itemind == pkind && p->firstunspentind > ramchain->unspentind )
                {
                    printf("%p itemind.%d pkind.%d firstunspent.%d != %d unspentind?\n",p,ptr->hh.itemind,pkind,p->firstunspentind,ramchain->unspentind);
                    return(-9);
                }
            }
        }
        else
        {
            for (k=0; k<t->numvouts; k++,ramchain->unspentind++)
            {
                if ( U[ramchain->unspentind].txidind != ramchain->txidind )
                {
                    printf(" k.%d U.%d u->txidind.%x != txidind.%d\n",k,ramchain->unspentind,U[ramchain->unspentind].txidind,ramchain->txidind);
                    return(-6);
                }
            }
        }
        ramchain->spendind += t->numvins;
    }
    ramchain->spendind = rdata->firsti;
    for (ramchain->txidind=rdata->firsti; ramchain->txidind<rdata->numtxids; ramchain->txidind++)
    {
        t = &T[ramchain->txidind];
        for (k=0; k<t->numvins; k++,ramchain->spendind++)
        {
            if ( ramchain->numblocks > 1 )
            {
                //printf("item.%p [%d] X.%p k.%d txidind.%d/%d spendind.%d/%d s->txidind.%x/v%d\n",rdata,rdata->numexternaltxids,X,k,ramchain->txidind,rdata->numtxids,spendind,rdata->numspends,s->spendtxidind,s->vout);
                if ( (vout= iguana_ramchain_txid(coin,RAMCHAIN_ARG,&txid,&Sx[ramchain->spendind])) < -1 )
                {
                    printf("txidind.%d k.%d error getting txid firsti.%d X.%d vout.%d spend.%x/%d numX.%d numT.%d\n",ramchain->txidind,k,rdata->firsti,ramchain->externalind,vout,Sx[ramchain->spendind].spendtxidind,rdata->numspends,rdata->numexternaltxids,rdata->numtxids);
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
    if ( ramchain->numblocks > 1 && ramchain->A != ramchain->roA )
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
    if ( ramchain->ROflag != 0 && ramchain->hashmem == 0 )
    {
        //printf("Free A %p %p, U2, P2\n",ramchain->A,ramchain->roA);
        if ( ramchain->A != ramchain->roA )
            myfree(ramchain->A,sizeof(*ramchain->A) * ramchain->data->numpkinds), ramchain->A = 0;
        if ( ramchain->U2 != ramchain->roU2 )
            myfree(ramchain->U2,sizeof(*ramchain->U2) * ramchain->data->numunspents), ramchain->U2 = 0;
        if ( ramchain->P2 != ramchain->roP2 )
            myfree(ramchain->P2,sizeof(*ramchain->P2) * ramchain->data->numpkinds), ramchain->P2 = 0;
    }
    if ( ramchain->txids != 0 )
        iguana_hashfree(ramchain->txids,deleteflag);
    if ( ramchain->pkhashes != 0 )
        iguana_hashfree(ramchain->pkhashes,deleteflag);
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
    if ( ramchain->numblocks > 1 )
    {
        _iguana_ramchain_setptrs(RAMCHAIN_PTRS);
        if ( (ramchain->hashmem= hashmem) != 0 )
            iguana_memreset(hashmem);
        ramchain->A = (hashmem != 0) ? iguana_memalloc(hashmem,sizeof(struct iguana_account) * ramchain->data->numpkinds,1) : mycalloc('p',ramchain->data->numpkinds,sizeof(struct iguana_account));
        ramchain->P2 = (hashmem != 0) ? iguana_memalloc(hashmem,sizeof(struct iguana_pkextra) * ramchain->data->numpkinds,1) : mycalloc('2',ramchain->data->numpkinds,sizeof(struct iguana_pkextra));
        ramchain->U2 = (hashmem != 0) ? iguana_memalloc(hashmem,sizeof(struct iguana_Uextra) * ramchain->data->numunspents,1) : mycalloc('3',ramchain->data->numunspents,sizeof(struct iguana_Uextra));
        printf("iguana_ramchain_extras A.%p:%p U2.%p:%p P2.%p:%p\n",ramchain->A,ramchain->roA,ramchain->U2,ramchain->roU2,ramchain->P2,ramchain->roP2);
        memcpy(ramchain->U2,ramchain->roU2,sizeof(*ramchain->U2) * ramchain->data->numunspents);
        memcpy(ramchain->P2,ramchain->roP2,sizeof(*ramchain->P2) * ramchain->data->numpkinds);
    }
}

struct iguana_ramchain *iguana_ramchain_map(struct iguana_info *coin,struct iguana_ramchain *ramchain,struct iguana_memspace *hashmem,uint32_t ipbits,bits256 hash2,int32_t bundlei,long fpos,int32_t allocextras)
{
    int32_t checki,hdrsi; char fname[1024],str[65],str2[65]; long filesize; void *ptr;
    if ( (checki= iguana_peerfname(coin,&hdrsi,fname,ipbits,hash2)) != bundlei || bundlei < 0 || bundlei >= coin->chain->bundlesize )
    {
        printf("iguana_ramchain_map.(%s) illegal hdrsi.%d bundlei.%d\n",fname,hdrsi,bundlei);
        return(0);
    }
    memset(ramchain,0,sizeof(*ramchain));
    if ( (ptr= map_file(fname,&filesize,0)) != 0 )
    {
        ramchain->fileptr = ptr;
        ramchain->data = (void *)((long)ptr + fpos);
        ramchain->filesize = (long)filesize;
        ramchain->ROflag = 1;
        printf("ptr.%p %p mapped P[%d] fpos.%d + %ld -> %ld vs %ld\n",ptr,ramchain->data,(int32_t)ramchain->data->Poffset,(int32_t)fpos,(long)ramchain->data->allocsize,(long)(fpos + ramchain->data->allocsize),filesize);
        if ( iguana_ramchain_size(ramchain) != ramchain->data->allocsize || fpos+ramchain->data->allocsize > filesize )
        {
            printf("iguana_ramchain_map.(%s) size mismatch %ld vs %ld vs filesize.%ld\n",fname,(long)iguana_ramchain_size(ramchain),(long)ramchain->data->allocsize,(long)filesize);
            munmap(ptr,filesize);
        }
        else if ( memcmp(hash2.bytes,ramchain->data->firsthash2.bytes,sizeof(bits256)) != 0 )
        {
            printf("iguana_ramchain_map.(%s) hash2 mismatch %s vs %s\n",fname,bits256_str(str,hash2),bits256_str(str2,ramchain->data->firsthash2));
            munmap(ptr,filesize);
        }
        else if ( ramchain->data->numblocks > 1 )
        {
            if ( allocextras != 0 )
                iguana_ramchain_extras(ramchain,hashmem);
        }
        return(ramchain);
    } else printf("iguana_ramchain_map.(%s) cant map file\n",fname);
    return(0);
}

void iguana_ramchain_link(struct iguana_ramchain *ramchain,bits256 firsthash2,bits256 lasthash2,int32_t hdrsi,int32_t height,int32_t numblocks,int32_t firsti,int32_t ROflag)
{
    if ( ROflag == 0 )
    {
        ramchain->data->firsthash2 = firsthash2;
        ramchain->data->lasthash2 = lasthash2;
        ramchain->data->hdrsi = hdrsi;
        ramchain->data->height = height;
        ramchain->data->numblocks = numblocks;
    }
    ramchain->hdrsi = hdrsi;
    ramchain->height = height;
    ramchain->numblocks = numblocks;
    ramchain->txidind = ramchain->unspentind = ramchain->spendind = ramchain->pkind = firsti;
    ramchain->externalind = 0;
}

int32_t iguana_ramchain_cmp(struct iguana_ramchain *A,struct iguana_ramchain *B,int32_t deepflag)
{
    int32_t i; char str[65],str2[65];
    struct iguana_txid *Ta,*Tb; struct iguana_unspent20 *Ua,*Ub; struct iguana_spend256 *Sa,*Sb;
    struct iguana_pkhash *Pa,*Pb; bits256 *Xa,*Xb; struct iguana_Uextra *U2a,*U2b;
    struct iguana_pkextra *P2a,*P2b; struct iguana_account *ACCTa,*ACCTb; struct iguana_unspent *Uxa,*Uxb;
    struct iguana_spend *Sxa,*Sxb;
    
    if ( A->data != 0 && B->data != 0 && A->data->numblocks == B->data->numblocks && memcmp(A->data->firsthash2.bytes,B->data->firsthash2.bytes,sizeof(A->data->firsthash2)) == 0 )
    {
        if ( A->data->firsti == B->data->firsti && A->data->numtxids == B->data->numtxids && A->data->numunspents == B->data->numunspents && A->data->numspends == B->data->numspends && A->data->numpkinds == B->data->numpkinds && A->data->numexternaltxids == B->data->numexternaltxids )
        {
            _iguana_ramchain_setptrs(A,&Ta,&Ua,&U2a,&Sa,&Pa,&P2a,&ACCTa,&Xa,&Uxa,&Sxa);
            _iguana_ramchain_setptrs(B,&Tb,&Ub,&U2b,&Sb,&Pb,&P2b,&ACCTb,&Xb,&Uxb,&Sxb);
            for (i=A->data->firsti; i<A->data->numtxids; i++)
                if ( memcmp(&Ta[i],&Tb[i],sizeof(Ta[i])) != 0 )
                    return(-2);
            if ( A->numblocks > 1 )
            {
                for (i=A->data->firsti; i<A->data->numspends; i++)
                    if ( memcmp(&Sxa[i],&Sxb[i],sizeof(Sxa[i])) != 0 )
                        return(-3);
                for (i=A->data->firsti; i<A->data->numunspents; i++)
                {
                    if ( memcmp(&Uxa[i],&Uxb[i],sizeof(Uxa[i])) != 0 )
                        return(-4);
                    if ( memcmp(&U2a[i],&U2b[i],sizeof(U2a[i])) != 0 )
                        return(-5);
                }
                for (i=A->data->firsti; i<A->data->numpkinds; i++)
                {
                    if ( memcmp(&P2a[i],&P2b[i],sizeof(P2a[i])) != 0 )
                        return(-6);
                    if ( memcmp(&ACCTa[i],&ACCTb[i],sizeof(ACCTa[i])) != 0 )
                        return(-7);
                }
                for (i=0; i<A->data->numexternaltxids; i++)
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
                for (i=A->data->firsti; i<A->data->numspends; i++)
                    if ( memcmp(&Sa[i],&Sb[i],sizeof(Sa[i])) != 0 )
                        return(-9);
                for (i=A->data->firsti; i<A->data->numunspents; i++)
                    if ( memcmp(&Ua[i],&Ub[i],sizeof(Ua[i])) != 0 )
                        return(-10);
            }
        }
        return(0);
    }
    printf("cmp %p %p, numblocks %d:%d %d:%d %s %s\n",A->data,B->data,A->numblocks,A->data->numblocks,B->numblocks,B->data->numblocks,bits256_str(str,A->data->firsthash2),bits256_str(str2,B->data->firsthash2));
    return(-1);
}

int32_t iguana_ramchain_iterate(struct iguana_info *coin,struct iguana_ramchain *ramchain)
{
    RAMCHAIN_DECLARE; int32_t j,prevout; uint32_t sequence; bits256 prevhash; struct iguana_txid *tx; struct iguana_ramchaindata *rdata;
    _iguana_ramchain_setptrs(RAMCHAIN_PTRS);
    if ( (rdata= ramchain->data) == 0 )
        return(-1);
    ramchain->ROflag = 1;
    ramchain->unspentind = ramchain->spendind = ramchain->pkind = rdata->firsti;
    ramchain->externalind = 0;
    for (ramchain->txidind=rdata->firsti; ramchain->txidind<rdata->numtxids; ramchain->txidind++)
    {
        tx = &T[ramchain->txidind];
        iguana_ramchain_addtxid(coin,RAMCHAIN_ARG,tx->txid,tx->numvouts,tx->numvins);
        for (j=0; j<tx->numvouts; j++)
        {
            //printf("unspentind.%d pkind.%d\n",ramchain->unspentind,U[ramchain->unspentind].pkind);
            if ( ramchain->numblocks > 1 )
            {
                iguana_ramchain_addunspent(coin,RAMCHAIN_ARG,U[ramchain->unspentind].value,P[Ux[ramchain->unspentind].pkind].rmd160);
            }
            else iguana_ramchain_addunspent20(coin,RAMCHAIN_ARG,U[ramchain->unspentind].value,U[ramchain->unspentind].rmd160,-20,tx->txid,j);
        }
        ramchain->spendind += tx->numvins;
    }
    ramchain->txidind = ramchain->spendind = rdata->firsti;
    for (ramchain->txidind=rdata->firsti; ramchain->txidind<rdata->numtxids; ramchain->txidind++)
    {
        tx = &T[ramchain->txidind];
        for (j=0; j<tx->numvins; j++,ramchain->spendind++)
        {
            if ( ramchain->numblocks > 1 )
            {
                prevout = iguana_ramchain_txid(coin,RAMCHAIN_ARG,&prevhash,&Sx[j]);
                char str[65]; printf("vin.%d %s vout.%d\n",j,bits256_str(str,prevhash),prevout);
                iguana_ramchain_addspend(coin,RAMCHAIN_ARG,prevhash,prevout,sequence,rdata->hdrsi);
            }
            else
            {
                sequence = (S[j].diffsequence == 0) ? 0xffffffff : 0;
                iguana_ramchain_addspend256(coin,RAMCHAIN_ARG,S[j].prevhash2,S[j].prevout,0,0,sequence,rdata->hdrsi);
            }
        }
    }
    return(0);
}

long iguana_blockramchainPT(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_txblock *origtxdata,struct iguana_msgtx *txarray,int32_t txn_count,uint8_t *data,int32_t recvlen)
{
    RAMCHAIN_DECLARE; long fsize; void *ptr; struct iguana_ramchain R,*mapchain,*ramchain = &addr->ramchain;
    struct iguana_msgtx *tx; int32_t i,j,firsti=1,err,flag,bundlei = -2; struct iguana_bundle *bp = 0;
    if ( iguana_bundlefind(coin,&bp,&bundlei,origtxdata->block.hash2) == 0 )
        return(-1);
    SETBIT(bp->recv,bundlei);
    bp->fpos[bundlei] = -1;
    bp->recvlens[bundlei] = recvlen;
    if ( iguana_ramchain_init(ramchain,&addr->TXDATA,&addr->HASHMEM,1,txn_count,origtxdata->numunspents,origtxdata->numspends,0,0) == 0 )
        return(-1);
    iguana_ramchain_link(ramchain,origtxdata->block.hash2,origtxdata->block.hash2,bp->hdrsi,bp->bundleheight+bundlei,1,firsti,0);
    _iguana_ramchain_setptrs(RAMCHAIN_PTRS);
    if ( T == 0 || U == 0 || S == 0 )// P == 0//|| X == 0 || A == 0 || U2 == 0 || P2 == 0 )
    {
        printf("fatal error getting txdataptrs\n");
        return(-1);
    }
    for (i=0; i<txn_count; i++,ramchain->txidind++)
    {
        tx = &txarray[i];
        iguana_ramchain_addtxid(coin,RAMCHAIN_ARG,tx->txid,tx->tx_out,tx->tx_in);
        for (j=0; j<tx->tx_out; j++)
        {
            iguana_ramchain_addunspent20(coin,RAMCHAIN_ARG,tx->vouts[j].value,tx->vouts[j].pk_script,tx->vouts[j].pk_scriptlen,tx->txid,j);
        }
        ramchain->spendind += tx->tx_in;
    }
    ramchain->txidind = ramchain->spendind = ramchain->data->firsti;
    for (i=0; i<txn_count; i++,ramchain->txidind++)
    {
        tx = &txarray[i];
        for (j=0; j<tx->tx_in; j++)
        {
            //char str[65]; printf("PT vin.%d %s vout.%d\n",j,bits256_str(str,tx->vins[j].prev_hash),tx->vins[j].prev_vout);
            iguana_ramchain_addspend256(coin,RAMCHAIN_ARG,tx->vins[j].prev_hash,tx->vins[j].prev_vout,tx->vins[j].script,tx->vins[j].scriptlen,tx->vins[j].sequence,bp->hdrsi);
        }
    }
    ramchain->data->numspends = ramchain->spendind;
    ramchain->data->numpkinds = ramchain->pkind;
    ramchain->data->numexternaltxids = ramchain->externalind;
    ramchain->data->allocsize = iguana_ramchain_size(ramchain);
    flag = 0;
    //char str[65]; printf("height.%d num.%d:%d T.%d U.%d S.%d P.%d X.%d %s\n",ramchain->height,ramchain->numblocks,ramchain->data->numblocks,ramchain->txidind,ramchain->unspentind,ramchain->spendind,ramchain->pkind,ramchain->externalind,bits256_str(str,ramchain->data->firsthash2));
    if ( ramchain->txidind != ramchain->data->numtxids || ramchain->unspentind != ramchain->data->numunspents || ramchain->spendind != ramchain->data->numspends )
    {
        printf("error creating PT ramchain: ramchain->txidind %d != %d ramchain->data->numtxids || ramchain->unspentind %d != %d ramchain->data->numunspents || ramchain->spendind %d != %d ramchain->data->numspends\n",ramchain->txidind,ramchain->data->numtxids,ramchain->unspentind,ramchain->data->numunspents,ramchain->spendind,ramchain->data->numspends);
    }
    else
    {
        if ( (err= iguana_ramchain_verify(coin,ramchain)) == 0 )
        {
            if ( (bp->fpos[bundlei]= iguana_ramchain_save(coin,RAMCHAIN_ARG,addr->ipbits,origtxdata->block.hash2,bundlei)) >= 0 )
            {
                bp->ipbits[bundlei] = addr->ipbits;
                ramchain->ROflag = 0;
                flag = 1;
                memset(&R,0,sizeof(R));
                if ( (mapchain= iguana_ramchain_map(coin,&R,0,addr->ipbits,origtxdata->block.hash2,bundlei,bp->fpos[bundlei],1)) != 0 )
                {
                    iguana_ramchain_link(&R,origtxdata->block.hash2,origtxdata->block.hash2,bp->hdrsi,bp->bundleheight+bundlei,1,firsti,1);
                    if ( 0 )
                    {
                        if ( (err= iguana_ramchain_cmp(ramchain,mapchain,0)) != 0 )
                            printf("error.%d comparing ramchains\n",err);
                        ptr = mapchain->fileptr; fsize = mapchain->filesize;
                        mapchain->fileptr = 0, mapchain->filesize = 0;
                        iguana_ramchain_free(mapchain,1);
                        memset(&R,0,sizeof(R));
                        R.data = (void *)((long)ptr + bp->fpos[bundlei]), R.filesize = fsize;
                        iguana_ramchain_link(&R,origtxdata->block.hash2,origtxdata->block.hash2,bp->hdrsi,bp->bundleheight+bundlei,1,firsti,1);
                    }
                    if ( (err= iguana_ramchain_cmp(ramchain,&R,0)) != 0 )
                        printf("error.%d comparing REMAP ramchains\n",err);
                    else if ( 1 )
                    {
                        iguana_ramchain_extras(&R,0);
                        if ( (err= iguana_ramchain_iterate(coin,&R)) != 0 )
                            printf("err.%d iterate ",err);
                        //printf("SUCCESS REMAP\n");
                    }
                    iguana_ramchain_free(&R,0);
                }
            }
        } else printf("ramchain verification error.%d hdrsi.%d bundlei.%d\n",err,bp->hdrsi,bundlei);
    }
    ramchain->ROflag = 0;
    //if ( flag == 0 )
        iguana_ramchain_free(ramchain,0);
    return(bp->fpos[bundlei]);
}

// two passes to check data size
int32_t iguana_rwvin(int32_t rwflag,struct iguana_memspace *mem,uint8_t *serialized,struct iguana_msgvin *msg)
{
    int32_t len = 0;
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(msg->prev_hash),msg->prev_hash.bytes);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->prev_vout),&msg->prev_vout);
    //char str[65]; printf("MSGvin.(%s) %d\n",bits256_str(str,msg->prev_hash),msg->prev_vout);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->scriptlen);
    if ( rwflag == 0 )
        msg->script = iguana_memalloc(mem,msg->scriptlen,1);
    len += iguana_rwmem(rwflag,&serialized[len],msg->scriptlen,msg->script);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->sequence),&msg->sequence);
    //int i; for (i=0; i<msg->scriptlen; i++)
    // printf("%02x ",msg->script[i]);
    //printf(" inscriptlen.%d, prevhash.%llx prev_vout.%d | ",msg->scriptlen,(long long)msg->prev_hash.txid,msg->prev_vout);
    return(len);
}

int32_t iguana_rwvout(int32_t rwflag,struct iguana_memspace *mem,uint8_t *serialized,struct iguana_msgvout *msg)
{
    int32_t len = 0;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->value),&msg->value);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->pk_scriptlen);
    if ( rwflag == 0 )
        msg->pk_script = iguana_memalloc(mem,msg->pk_scriptlen,1);
    len += iguana_rwmem(rwflag,&serialized[len],msg->pk_scriptlen,msg->pk_script);
    //printf("(%.8f scriptlen.%d) ",dstr(msg->value),msg->pk_scriptlen);
    //int i; for (i=0; i<msg->pk_scriptlen; i++)
    //    printf("%02x",msg->pk_script[i]);
    //printf("\n");
    return(len);
}

int32_t iguana_rwtx(int32_t rwflag,struct iguana_memspace *mem,uint8_t *serialized,struct iguana_msgtx *msg,int32_t maxsize,bits256 *txidp,int32_t height,int32_t hastimestamp)
{
    int32_t i,len = 0; uint8_t *txstart = serialized; char txidstr[65]; uint32_t timestamp;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->version),&msg->version);
    if ( hastimestamp != 0 )
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(timestamp),&timestamp);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->tx_in);
    //printf("version.%d ",msg->version);
    if ( msg->tx_in > 0 && msg->tx_out*100 < maxsize )
    {
        if ( rwflag == 0 )
            msg->vins = iguana_memalloc(mem,msg->tx_in * sizeof(*msg->vins),1);
        for (i=0; i<msg->tx_in; i++)
            len += iguana_rwvin(rwflag,mem,&serialized[len],&msg->vins[i]);
        //printf("numvins.%d\n",msg->tx_in);
    }
    else
    {
        printf("invalid tx_in.%d\n",msg->tx_in);
        return(-1);
    }
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->tx_out);
    if ( msg->tx_out > 0 && msg->tx_out*32 < maxsize )
    {
        //printf("numvouts.%d ",msg->tx_out);
        if ( rwflag == 0 )
            msg->vouts = iguana_memalloc(mem,msg->tx_out * sizeof(*msg->vouts),1);
        for (i=0; i<msg->tx_out; i++)
            len += iguana_rwvout(rwflag,mem,&serialized[len],&msg->vouts[i]);
    }
    else
    {
        printf("invalid tx_out.%d\n",msg->tx_out);
        return(-1);
    }
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->lock_time),&msg->lock_time);
    *txidp = bits256_doublesha256(txidstr,txstart,len);
    msg->allocsize = len;
    return(len);
}

int32_t iguana_gentxarray(struct iguana_info *coin,struct iguana_memspace *mem,struct iguana_txblock *txdata,int32_t *lenp,uint8_t *data,int32_t datalen)
{
    struct iguana_msgtx *tx; bits256 hash2; struct iguana_msgblock msg; int32_t i,n,len,numvouts,numvins;
    memset(&msg,0,sizeof(msg));
    len = iguana_rwblock(0,&hash2,data,&msg);
    iguana_blockconv(&txdata->block,&msg,hash2,-1);
    tx = iguana_memalloc(mem,msg.txn_count*sizeof(*tx),1);
    for (i=numvins=numvouts=0; i<msg.txn_count; i++)
    {
        if ( (n= iguana_rwtx(0,mem,&data[len],&tx[i],datalen - len,&tx[i].txid,txdata->block.height,coin->chain->hastimestamp)) < 0 )
            break;
        numvouts += tx[i].tx_out;
        numvins += tx[i].tx_in;
        len += n;
    }
    if ( coin->chain->hastimestamp != 0 && len != datalen && data[len] == (datalen - len - 1) )
    {
        //printf("\n>>>>>>>>>>> len.%d vs datalen.%d [%d]\n",len,datalen,data[len]);
        memcpy(txdata->space,&data[len],datalen-len);
        len += (datalen-len);
        txdata->extralen = (datalen - len);
    } else txdata->extralen = 0;
    txdata->recvlen = len;
    txdata->numtxids = msg.txn_count;
    txdata->numunspents = numvouts;
    txdata->numspends = numvins;
    return(len);
}

// threadsafe
void iguana_emitQ(struct iguana_info *coin,struct iguana_bundle *bp)
{
    struct iguana_helper *ptr;
    ptr = mycalloc('i',1,sizeof(*ptr));
    ptr->allocsize = sizeof(*ptr);
    ptr->coin = coin;
    ptr->bp = bp, ptr->hdrsi = bp->hdrsi;
    ptr->type = 'E';
    printf("%s EMIT.%d[%d] emitfinish.%u\n",coin->symbol,ptr->hdrsi,bp->n,bp->emitfinish);
    queue_enqueue("helperQ",&helperQ,&ptr->DL,0);
}

void iguana_ramchain_disp(struct iguana_ramchain *ramchain)
{
    RAMCHAIN_DECLARE; int32_t j; uint32_t txidind,unspentind,spendind; struct iguana_txid *tx; char str[65];
    _iguana_ramchain_setptrs(RAMCHAIN_PTRS);
    if ( ramchain->data != 0 )
    {
        unspentind = spendind = ramchain->data->firsti;
        for (txidind=ramchain->data->firsti; txidind<ramchain->data->numtxids; txidind++)
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

// helper threads: NUM_HELPERS
int32_t iguana_bundlesaveHT(struct iguana_info *coin,struct iguana_memspace *mem,struct iguana_memspace *memB,struct iguana_bundle *bp) // helper thread
{
    struct iguana_ramchain R,*mapchain; int32_t bundlei,firsti = 1;
    for (bundlei=0; bundlei<bp->n; bundlei++)
    {
        memset(&R,0,sizeof(R));
        if ( (mapchain= iguana_ramchain_map(coin,&R,0,bp->ipbits[bundlei],bp->hashes[bundlei],bundlei,bp->fpos[bundlei],1)) != 0 )
        {
            iguana_ramchain_link(mapchain,bp->hashes[bundlei],bp->hashes[bundlei],bp->hdrsi,bp->bundleheight+bundlei,1,firsti,1);
            iguana_ramchain_disp(mapchain);
            iguana_ramchain_free(mapchain,0);
        } else printf("map error hdrs.%d:%d\n",bp->hdrsi,bundlei);
    }
/*    struct iguana_txblock *ptr; struct iguana_ramchain *ptrs[IGUANA_MAXBUNDLESIZE],*ramchains;
    struct iguana_block *block; char fname[1024]; uint64_t estimatedsize = 0;
    int32_t i,maxrecv,addrind,flag,bundlei,numdirs=0; struct iguana_ramchain *ramchain;
    flag = maxrecv = 0;
    memset(ptrs,0,sizeof(ptrs));
    ramchains = mycalloc('p',coin->chain->bundlesize,sizeof(*ramchains));
    for (i=0; i<bp->n && i<coin->chain->bundlesize; i++)
    {
        if ( (block= iguana_blockfind(coin,bp->hashes[i])) != 0 )
        {
            iguana_meminit(&memB[i],"ramchainB",0,block->recvlen*2 + 8192,0);
            if ( (ptr= iguana_peertxdata(coin,&bundlei,fname,&memB[i],block->ipbits,block->hash2)) != 0 )
            {
                if ( bundlei != i || ptr->block.bundlei != i )
                    printf("peertxdata.%d bundlei.%d, i.%d block->bundlei.%d\n",bp->hdrsi,bundlei,i,ptr->block.bundlei);
                ptrs[i] = &ramchains[i];
                //char str[65];
                //printf("received txdata.%s bundlei.%d T.%d U.%d S.%d P.%d\n",bits256_str(str,ptr->block.hash2),bundlei,ptr->numtxids,ptr->numunspents,ptr->numspends,ptr->numpkinds);
                if ( iguana_ramchainset(coin,ptrs[i],ptr) == ptrs[i] )
                {
                    char str[65]; int32_t err;
                    //for (j=0; j<ptrs[i]->numpkinds; j++)
                    //    init_hexbytes_noT(str,ptrs[i]->P[j].rmd160,20), printf("%s ",str);
                    err = iguana_ramchainverifyPT(coin,ptrs[i]);
                    printf("conv err.%d ramchain.%s bundlei.%d T.%d U.%d S.%d P.%d\n",err,bits256_str(str,ptrs[i]->data->firsthash2),bundlei,ptrs[i]->data->numtxids,ptrs[i]->data->numunspents,ptrs[i]->data->numspends,ptrs[i]->data->numpkinds);
                    ptrs[i]->data->firsti = 0;
                    if ( block->recvlen > maxrecv )
                        maxrecv = block->recvlen;
                    estimatedsize += block->recvlen;
                    flag++;
                } else printf("error setting ramchain.%d\n",i);
            }
            else
            {
                printf("error (%s) hdrs.%d ptr[%d]\n",fname,bp->hdrsi,i);
                CLEARBIT(bp->recv,i);
                bp->issued[i] = 0;
                block = 0;
            }
        }
    }
    if ( flag == i )
    {
        printf("numpkinds >>>>>>>>> start MERGE.(%ld) i.%d flag.%d estimated.%ld maxrecv.%d\n",(long)mem->totalsize,i,flag,(long)estimatedsize,maxrecv);
        if ( (ramchain= iguana_ramchainmergeHT(coin,mem,ptrs,i,bp)) != 0 )
        {
            iguana_ramchainsave(coin,ramchain);
            iguana_ramchainfree(coin,mem,ramchain);
            //printf("ramchain saved\n");
            bp->emitfinish = (uint32_t)time(NULL);
            for (addrind=0; addrind<IGUANA_MAXPEERS; addrind++)
            {
                if ( coin->peers.active[addrind].ipbits != 0 )
                {
                    if ( iguana_peerfile_exists(coin,&coin->peers.active[addrind],fname,bp->hashes[0]) >= 0 )
                    {
                        //printf("remove.(%s)\n",fname);
                        //iguana_removefile(fname,0);
                        //coin->peers.numfiles--;
                    }
                }
            }
        } else bp->emitfinish = 0;
    }
    else
    {
        printf(">>>>> bundlesaveHT error: numdirs.%d i.%d flag.%d\n",numdirs,i,flag);
        bp->emitfinish = 0;
    }
    for (i=0; i<bp->n && i<coin->chain->bundlesize; i++)
        iguana_mempurge(&memB[i]);
    myfree(ramchains,coin->chain->bundlesize * sizeof(*ramchains));
    return(flag);*/
    return(0);
}

int32_t iguana_helpertask(FILE *fp,struct iguana_memspace *mem,struct iguana_memspace *memB,struct iguana_helper *ptr)
{
    struct iguana_info *coin; struct iguana_peer *addr; struct iguana_bundle *bp;
    coin = ptr->coin, addr = ptr->addr;
    /*if ( ptr->type == 'F' )
    {
        if ( addr != 0 && addr->fp != 0 )
        {
            //printf("flush.%s %p\n",addr->ipaddr,addr->fp);
            fflush(addr->fp);
        }
    }
    else*/ if ( ptr->type == 'E' )
    {
        printf("emitQ coin.%p bp.%p\n",ptr->coin,ptr->bp);
        if ( (coin= ptr->coin) != 0 )
        {
            if ( (bp= ptr->bp) != 0 )
            {
                bp->emitfinish = (uint32_t)time(NULL);
//#ifdef __APPLE__
                if ( iguana_bundlesaveHT(coin,mem,memB,bp) == 0 )
//#endif
                    coin->numemitted++;
            } else printf("error missing bp in emit\n");
            //printf("MAXBUNDLES.%d vs max.%d estsize %ld vs cache.%ld\n",coin->MAXBUNDLES,_IGUANA_MAXBUNDLES,(long)coin->estsize,(long)coin->MAXRECVCACHE);
            if ( coin->MAXBUNDLES > IGUANA_MAXACTIVEBUNDLES || (coin->estsize > coin->MAXRECVCACHE*.9 && coin->MAXBUNDLES > _IGUANA_MAXBUNDLES) )
                coin->MAXBUNDLES--;
            else if ( (coin->MAXBUNDLES * coin->estsize)/(coin->activebundles+1) < coin->MAXRECVCACHE*.75 )
                coin->MAXBUNDLES += (coin->MAXBUNDLES >> 2) + 1;
            else printf("no change to MAXBUNDLES.%d\n",coin->MAXBUNDLES);
        } else printf("no coin in helper request?\n");
    }
    return(0);
}

void iguana_helper(void *arg)
{
    FILE *fp = 0; char fname[512],name[64],*helpername = 0; cJSON *argjson=0; int32_t i,flag;
    struct iguana_helper *ptr; struct iguana_info *coin; struct iguana_memspace MEM,*MEMB;
    if ( arg != 0 && (argjson= cJSON_Parse(arg)) != 0 )
        helpername = jstr(argjson,"name");
    if ( helpername == 0 )
    {
        sprintf(name,"helper.%d",rand());
        helpername = name;
    }
    sprintf(fname,"tmp/%s",helpername);
    fp = fopen(fname,"wb");
    if ( argjson != 0 )
        free_json(argjson);
    memset(&MEM,0,sizeof(MEM));
    MEMB = mycalloc('b',IGUANA_MAXBUNDLESIZE,sizeof(*MEMB));
    while ( 1 )
    {
        flag = 0;
        while ( (ptr= queue_dequeue(&helperQ,0)) != 0 )
        {
            iguana_helpertask(fp,&MEM,MEMB,ptr);
            myfree(ptr,ptr->allocsize);
            flag++;
        }
        if ( flag == 0 )
        {
            for (i=0; i<sizeof(Coins)/sizeof(*Coins); i++)
            {
                if ( (coin= Coins[i]) != 0 && coin->launched != 0 )
                    flag += iguana_rpctest(coin);
            }
            if ( flag == 0 )
                usleep(10000);
        }
    }
}

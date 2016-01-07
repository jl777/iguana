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

//#define HASH_BLOOM 16
//#define HASH_INITIAL_NUM_BUCKETS_LOG2 5

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
            printf("negative itemind\n"), exit(-1);
        if ( tmp != ptr )
        {
            printf("(%s) hashmem.%p selector.%c %s search error %p != %p itemind.%x\n",str,ramchain->hashmem,selector,str,ptr,tmp,itemind), exit(-1);
        }
    }
    return(ptr);
}

uint32_t iguana_sparseadd(uint8_t *bits,uint32_t ind,int32_t width,uint32_t tablesize,uint8_t *key,int32_t keylen,uint32_t setind,void *refdata,int32_t refsize)
{
    static long sparsesearches,sparseiters,sparsehits,sparsemax;
    static uint8_t masks[8] = { 1, 2, 4, 8, 16, 32, 64, 128 };
    int32_t i,j,x,n,modval; int64_t bitoffset; uint8_t *ptr;
    if ( tablesize == 0 )
    {
        printf("iguana_sparseadd tablesize zero illegal\n");
        return(0);
    }
    if ( 0 && setind == 0 )
    {
        char str[65];
        for (i=n=0; i<tablesize; i++)
        {
            bitoffset = (i * width);
            ptr = &bits[bitoffset >> 3];
            modval = (bitoffset & 7);
            for (x=j=0; j<width; j++,modval++)
            {
                if ( modval >= 8 )
                    ptr++, modval = 0;
                x <<= 1;
                x |= (*ptr & masks[modval]) >> modval;
            }
            if ( x != 0 )
                printf("%s ",bits256_str(str,*(bits256 *)(refdata + x*refsize))), n++;
        }
        printf("tableentries.%d\n",n);
    }
    bitoffset = (ind * width);
    sparsesearches++;
    if ( 0 && setind == 0 )
        printf("tablesize.%d width.%d bitoffset.%d\n",tablesize,width,(int32_t)bitoffset);
    for (i=0; i<tablesize; i++,ind++,bitoffset+=width)
    {
        sparseiters++;
        if ( ind >= tablesize )
        {
            ind = 0;
            bitoffset = 0;
        }
        ptr = &bits[bitoffset >> 3];
        modval = (bitoffset & 7);
        if ( 0 && setind == 0 )
            printf("tablesize.%d width.%d bitoffset.%d modval.%d i.%d\n",tablesize,width,(int32_t)bitoffset,modval,i);
        for (x=j=0; j<width; j++,modval++)
        {
            if ( modval >= 8 )
                ptr++, modval = 0;
            x <<= 1;
            x |= (*ptr & masks[modval]) >> modval;
        }
        if ( 0 && setind == 0 )
            printf("x.%d\n",x);
        if ( x == 0 )
        {
            if ( (x= setind) == 0 )
                return(0);
            ptr = &bits[(bitoffset+width-1) >> 3];
            modval = ((bitoffset+width-1) & 7);
            for (j=0; j<width; j++,x>>=1,modval--)
            {
                if ( modval < 0 )
                    ptr--, modval = 7;
                if ( (x & 1) != 0 )
                    *ptr |= masks[modval];
            }
            if ( 0 )
            {
                for (x=j=0; j<width; j++)
                {
                    x <<= 1;
                    x |= GETBIT(bits,bitoffset+j) != 0;
                }
                if ( x != setind )
                    printf("x.%d vs setind.%d ind.%d bitoffset.%d\n",x,setind,ind,(int32_t)bitoffset);
                if ( (rand() % 10000) == 0 )
                    printf("[%d %d] %.3f sparse searches.%ld iters.%ld hits.%ld max.%ld\n",width,tablesize,(double)sparseiters/(1+sparsesearches),sparsesearches,sparseiters,sparsehits,sparsemax+1);
            }
            if ( i > sparsemax )
                sparsemax = i;
            return(setind);
        }
        else if ( memcmp((void *)((long)refdata + x*refsize),key,keylen) == 0 )
        {
            if ( setind == 0 )
                sparsehits++;
            else if ( setind != x )
                printf("sparseadd index collision setind.%d != x.%d\n",setind,x);
            return(x);
        }
    }
    return(0);
}

uint32_t iguana_sparseaddtx(uint8_t *bits,int32_t width,uint32_t tablesize,bits256 txid,struct iguana_txid *T,uint32_t txidind)
{
    uint32_t ind;
    ind = (txid.ulongs[0] ^ txid.ulongs[1] ^ txid.ulongs[2] ^ txid.ulongs[3]) % tablesize;
    return(iguana_sparseadd(bits,ind,width,tablesize,txid.bytes,sizeof(txid),txidind,T,sizeof(*T)));
}

uint32_t iguana_sparseaddpk(uint8_t *bits,int32_t width,uint32_t tablesize,uint8_t rmd160[20],struct iguana_pkhash *P,uint32_t pkind)
{
    uint32_t ind,key2; uint64_t key0,key1;
    memcpy(&key0,rmd160,sizeof(key0));
    memcpy(&key1,&rmd160[sizeof(key0)],sizeof(key1));
    memcpy(&key2,&rmd160[sizeof(key0) + sizeof(key1)],sizeof(key2));
    ind = (key0 ^ key1 ^ key2) % tablesize;
    return(iguana_sparseadd(bits,ind,width,tablesize,rmd160,20,pkind,P,sizeof(*P)));
}

void iguana_blocksetcounters(struct iguana_info *coin,struct iguana_block *block,struct iguana_ramchain * ramchain)
{
    block->RO.firsttxidind = ramchain->H.txidind;
    block->RO.firstvout = ramchain->H.unspentind;
    block->RO.firstvin = ramchain->H.spendind;
    block->RO.firstpkind = ramchain->pkind;
    block->RO.firstexternalind = ramchain->externalind;
}

struct iguana_txid *iguana_txidfind(struct iguana_info *coin,int32_t *heightp,struct iguana_txid *tx,bits256 txid)
{
    uint8_t *TXbits; struct iguana_txid *T; uint32_t txidind,i,j;
    struct iguana_bundle *bp; struct iguana_ramchain *ramchain; struct iguana_block *block;
    *heightp = -1;
    for (i=0; i<coin->bundlescount; i++)
    {
        if ( (bp= coin->bundles[i]) != 0 && bp->emitfinish > coin->startutc )
        {
            ramchain = &bp->ramchain;
            if ( ramchain->H.data != 0 )
            {
                TXbits = (void *)((long)ramchain->H.data + ramchain->H.data->TXoffset);
                T = (void *)((long)ramchain->H.data + ramchain->H.data->Toffset);
                //printf("search bp.%p TXbits.%p T.%p %d %d\n",bp,TXbits,T,(int32_t)ramchain->H.data->TXoffset,(int32_t)ramchain->H.data->Toffset);
                if ( (txidind= iguana_sparseaddtx(TXbits,ramchain->H.data->txsparsebits,ramchain->H.data->numtxsparse,txid,T,0)) > 0 )
                {
                    //printf("found txidind.%d\n",txidind);
                    for (j=0; j<bp->n; j++)
                        if ( (block= bp->blocks[j]) != 0 && txidind >= block->RO.firsttxidind && txidind < block->RO.firsttxidind+block->RO.txn_count )
                            break;
                    *heightp = bp->bundleheight + j;
                    //printf("found height.%d\n",*heightp);
                    *tx = T[txidind];
                    return(tx);
                }
            }
        }
    }
    return(0);
}

struct iguana_pkhash *iguana_pkhashfind(struct iguana_info *coin,struct iguana_pkhash *p,uint8_t rmd160[20])
{
    uint8_t *PKbits; struct iguana_pkhash *P; uint32_t pkind,i; struct iguana_bundle *bp; struct iguana_ramchain *ramchain;
    for (i=0; i<coin->bundlescount; i++)
    {
        if ( (bp= coin->bundles[i]) != 0 )
        {
            ramchain = &bp->ramchain;
            PKbits = (void *)((long)ramchain->H.data + ramchain->H.data->PKoffset);
            P = (void *)((long)ramchain->H.data + ramchain->H.data->Poffset);
            if ( (pkind= iguana_sparseaddpk(PKbits,ramchain->H.data->pksparsebits,ramchain->H.data->numpksparse,rmd160,P,0)) > 0 )
            {
                *p = P[pkind];
                return(p);
            }
        }
    }
    return(0);
}

int32_t iguana_peerfname(struct iguana_info *coin,int32_t *hdrsip,char *dirname,char *fname,uint32_t ipbits,bits256 hash2,bits256 prevhash2,int32_t numblocks)
{
    struct iguana_bundle *bp = 0; int32_t bundlei = -2; char str[65];
    *hdrsip = -1;
    //if ( ipbits == 0 )
    //    printf("illegal ipbits.%d\n",ipbits), getchar();
    if ( (bp= iguana_bundlefind(coin,&bp,&bundlei,hash2)) == 0 )
    {
        if ( bits256_nonz(prevhash2) == 0 || (bp= iguana_bundlefind(coin,&bp,&bundlei,prevhash2)) == 0 || bundlei >= coin->chain->bundlesize-1 )
            return(-2);
        else bundlei++;
    }
    hash2 = bp->hashes[0], *hdrsip = bp->hdrsi;
    if ( numblocks == 1 )
        sprintf(fname,"%s/%s/%s.%u",dirname,coin->symbol,bits256_str(str,hash2),ipbits!=0?ipbits:*hdrsip);
    else sprintf(fname,"%s/%s/%s_%d.%u",dirname,coin->symbol,bits256_str(str,hash2),numblocks,ipbits!=0?ipbits:*hdrsip);
    OS_compatible_path(fname);
    return(bundlei);
}

int32_t iguana_peerfile_exists(struct iguana_info *coin,struct iguana_peer *addr,char *dirname,char *fname,bits256 hash2,bits256 prevhash2,int32_t numblocks)
{
    FILE *fp; int32_t bundlei,hdrsi;
    if ( (bundlei= iguana_peerfname(coin,&hdrsi,dirname,fname,addr!=0?addr->ipbits:0,hash2,prevhash2,numblocks)) >= 0 )
    {
        OS_compatible_path(fname);
        if ( (fp= fopen(fname,"rb")) == 0 )
            bundlei = -1;
        else fclose(fp);
    }
    return(bundlei);
}

#define RAMCHAIN_FUNC struct iguana_ramchain *ramchain,struct iguana_blockRO *B,struct iguana_txid *T,struct iguana_unspent20 *U,struct iguana_spend256 *S,struct iguana_pkhash *P,struct iguana_account *A,bits256 *X,struct iguana_unspent *Ux,struct iguana_spend *Sx,uint8_t *TXbits,uint8_t *PKbits
#define RAMCHAIN_PTRPS struct iguana_ramchain *ramchain,struct iguana_blockRO **B,struct iguana_txid **T,struct iguana_unspent20 **U,struct iguana_spend256 **S,struct iguana_pkhash **P,struct iguana_account **A,bits256 **X,struct iguana_unspent **Ux,struct iguana_spend **Sx,uint8_t **TXbits,uint8_t **PKbits

#define _RAMCHAIN_ARG B,T,U,S,P,A,X,Ux,Sx,TXbits,PKbits
#define RAMCHAIN_ARG ramchain,_RAMCHAIN_ARG
#define MAPCHAIN_ARG mapchain,_RAMCHAIN_ARG
#define RAMCHAIN_PTRS ramchain,&B,&T,&U,&S,&P,&A,&X,&Ux,&Sx,&TXbits,&PKbits
#define RAMCHAIN_DECLARE struct iguana_blockRO *B; struct iguana_txid *T; struct iguana_unspent20 *U; struct iguana_spend256 *S; struct iguana_pkhash *P; struct iguana_account *A; bits256 *X; struct iguana_unspent *Ux; struct iguana_spend *Sx; uint8_t *TXbits,*PKbits;

#define RAMCHAIN_DESTARG dest,destB,destT,destU,destS,destP,destA,destX,destUx,destSx,destTXbits,destPKbits
#define RAMCHAIN_DESTPTRS dest,&destB,&destT,&destU,&destS,&destP,&destA,&destX,&destUx,&destSx,&destTXbits,&destPKbits
#define RAMCHAIN_DESTDECLARE struct iguana_blockRO *destB; struct iguana_txid *destT; struct iguana_unspent20 *destU; struct iguana_spend256 *destS; struct iguana_pkhash *destP; struct iguana_account *destA; bits256 *destX; struct iguana_unspent *destUx; struct iguana_spend *destSx; uint8_t *destTXbits,*destPKbits;

uint32_t iguana_ramchain_addtxid(struct iguana_info *coin,RAMCHAIN_FUNC,bits256 txid,int32_t numvouts,int32_t numvins,uint32_t locktime,uint32_t version,uint32_t timestamp)
{
    uint32_t txidind; struct iguana_txid *t; struct iguana_kvitem *ptr;
    txidind = ramchain->H.txidind;
    t = &T[txidind];
    if ( ramchain->H.ROflag != 0 )
    {
        if ( t->txidind != txidind || memcmp(t->txid.bytes,txid.bytes,sizeof(bits256)) != 0 || t->numvouts != numvouts || t->numvins != numvins || t->firstvout != ramchain->H.unspentind || t->firstvin != ramchain->H.spendind || t->locktime != locktime || t->version != version || t->timestamp != timestamp )
        {
            printf("iguana_ramchain_addtxid: addtxid mismatch (%d %d %d %d %d) vs. (%d %d %d %d %d)\n",t->txidind,t->numvouts,t->numvins,t->firstvout,t->firstvin,txidind,numvouts,numvins,ramchain->H.unspentind,ramchain->H.spendind);
            exit(-1);
            return(0);
        }
    }
    else
    {
        //if ( ramchain->expanded != 0 )
        //    printf("T.%p txidind.%d numvouts.%d numvins.%d\n",T,txidind,numvouts,numvins);
        t->txidind = txidind, t->txid = txid, t->numvouts = numvouts, t->numvins = numvins;
        t->firstvout = ramchain->H.unspentind, t->firstvin = ramchain->H.spendind;
        t->locktime = locktime, t->version = version, t->timestamp = timestamp;
        if ( ramchain->expanded != 0 )
            iguana_sparseaddtx(TXbits,ramchain->H.data->txsparsebits,ramchain->H.data->numtxsparse,txid,T,txidind);
        //if ( txidind <= 2 )
        //    printf("%p TXID.[%d] firstvout.%d/%d firstvin.%d/%d\n",t,txidind,ramchain->unspentind,numvouts,ramchain->spendind,numvins);
    }
    if ( ramchain->expanded != 0 )
    {
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
            if ( P[pkind].flags != flags || P[pkind].firstunspentind != unspentind || P[pkind].pkind != pkind )
            {
                printf("iguana_ramchain_addpkhash pkind.%d vs %d error mismatched flags.(%x %x) firstunspentind.%x vs %x\n",pkind,P[pkind].pkind,P[pkind].flags,flags,P[pkind].firstunspentind,unspentind);
                exit(-1);
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
            P[pkind].pkind = pkind;
            P[pkind].firstunspentind = unspentind;
            //printf("%p P[%d] <- firstunspent.%d\n",&P[pkind],pkind,unspentind);
            memcpy(P[pkind].rmd160,rmd160,sizeof(P[pkind].rmd160));
            if ( ramchain->expanded != 0 )
                iguana_sparseaddpk(PKbits,ramchain->H.data->pksparsebits,ramchain->H.data->numpksparse,rmd160,P,pkind);
        }
        if ( (ptr= iguana_hashsetPT(ramchain,'P',&P[pkind],pkind)) == 0 )
        {
            printf("iguana_ramchain_addpkhash error adding pkhash\n");
            return(0);
        }
    }
    return(pkind);
}

uint32_t iguana_ramchain_addunspent20(struct iguana_info *coin,RAMCHAIN_FUNC,uint64_t value,uint8_t *script,int32_t scriptlen,bits256 txid,int32_t vout,uint8_t type)
{
    //struct iguana_unspent { uint64_t value; uint32_t txidind,pkind,prevunspentind; } __attribute__((packed));
    uint8_t rmd160[20],msigs160[16][20]; int32_t M,N; uint32_t unspentind; struct iguana_unspent20 *u;
    unspentind = ramchain->H.unspentind++;
    u = &U[unspentind];
    if ( scriptlen == -20 )
        memcpy(rmd160,script,20);
    else type = iguana_calcrmd160(coin,rmd160,msigs160,&M,&N,script,scriptlen,txid);
    if ( ramchain->H.ROflag != 0 )
    {
        //printf("%p U[%d] txidind.%d pkind.%d\n",u,unspentind,ramchain->txidind,pkind);
        if ( u->txidind != ramchain->H.txidind || u->value != value || memcmp(u->rmd160,rmd160,sizeof(rmd160)) != 0 )
        {
            printf("iguana_ramchain_addunspent20: mismatched values.(%.8f %d) vs (%.8f %d)\n",dstr(u->value),u->txidind,dstr(value),ramchain->H.txidind);
            return(0);
        }
    }
    else
    {
        u->value = value;
        u->type = type;
        u->txidind = ramchain->H.txidind;
        memcpy(u->rmd160,rmd160,sizeof(rmd160));
    }
    return(unspentind);
}

uint32_t iguana_ramchain_addunspent(struct iguana_info *coin,RAMCHAIN_FUNC,uint64_t value,uint16_t hdrsi,uint8_t *rmd160,uint16_t vout,uint8_t type)
{
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
            printf("iguana_ramchain_addunspent: mismatched values.(%d %.8f %d %d %d %d) vs (%d %.8f %d %d %d %d)\n",u->pkind,dstr(u->value),u->txidind,u->prevunspentind,u->vout,u->hdrsi,pkind,dstr(value),ramchain->H.txidind,A[pkind].lastunspentind,vout,hdrsi);
            exit(-1);
            return(0);
        }
    }
    else
    {
        u->value = value;
        u->type = type;
        u->vout = vout, u->hdrsi = hdrsi;
        u->txidind = ramchain->H.txidind, u->pkind = pkind;
        u->prevunspentind = A[pkind].lastunspentind;
    }
    //printf("%p A[%d] last <- U%d\n",&A[pkind],pkind,unspentind);
    A[pkind].balance += value;
    A[pkind].lastunspentind = unspentind;
    return(unspentind);
}

uint32_t iguana_ramchain_addspend256(struct iguana_info *coin,RAMCHAIN_FUNC,bits256 prev_hash,int32_t prev_vout,uint8_t *script,int32_t scriptlen,uint32_t sequence)//,int32_t hdrsi,int32_t bundlei)
{
    struct iguana_spend256 *s; uint32_t spendind;
    spendind = ramchain->H.spendind++;
    s = &S[spendind];
    if ( ramchain->H.ROflag != 0 )
    {
        if ( (s->diffsequence == 0 && sequence != 0xffffffff) || (s->diffsequence != 0 && sequence == 0xffffffff) || memcmp(s->prevhash2.bytes,prev_hash.bytes,sizeof(bits256)) != 0 || s->prevout != prev_vout ) //|| s->hdrsi != hdrsi
        {
            char str[65],str2[65]; printf("check addspend.%d v %d RO value mismatch diffseq.%d seq.%x prev_vout(%d vs %d) %s vs %s\n",spendind,s->spendind,s->diffsequence,sequence,s->prevout,prev_vout,bits256_str(str,s->prevhash2),bits256_str(str2,prev_hash));
            //printf("check addspend.%d vs %d RO value mismatch (%d %d:%d) vs (%d %d:%d)\n",spendind,s->spendind,s->prevout,s->hdrsi,s->bundlei,prev_vout,hdrsi,bundlei);
            exit(-1);
            return(0);
        }
        //printf(" READ.%p spendind.%d vs %d prevout.%d hdrsi.%d:%d\n",s,spendind,s->spendind,s->prevout,s->hdrsi,s->bundlei);
    }
    else
    {
        if ( sequence != 0xffffffff )
            s->diffsequence = 1;
        s->prevhash2 = prev_hash, s->prevout = prev_vout;
        //s->hdrsi = hdrsi, s->bundlei = bundlei;
        s->spendind = spendind;
        //char str[65]; printf("W.%p s.%d vout.%d/%d %d:%d %s\n",s,spendind,s->prevout,prev_vout,s->hdrsi,s->bundlei,bits256_str(str,prev_hash));
    }
    return(spendind);
}

int32_t iguana_ramchain_spendtxid(struct iguana_info *coin,bits256 *txidp,struct iguana_txid *T,int32_t numtxids,bits256 *X,int32_t numexternaltxids,struct iguana_spend *s)
{
    uint32_t ind,external;
    memset(txidp,0,sizeof(*txidp));
    //printf("s.%p ramchaintxid vout.%x spendtxidind.%d numexternals.%d isext.%d numspendinds.%d\n",s,s->vout,s->spendtxidind,ramchain->numexternaltxids,s->external,ramchain->numspends);
    if ( s->prevout < 0 )
        return(-1);
    ind = s->spendtxidind;
    external = (ind >> 31) & 1;
    ind &= ~(1 << 31);
    if ( s->external != 0 && s->external == external && ind < numexternaltxids )
    {
        //printf("ind.%d externalind.%d X[%d]\n",ind,ramchain->externalind,ramchain->H.data->numexternaltxids);
        *txidp = X[ind];
        return(s->prevout);
    }
    else if ( s->external == 0 && s->external == external && ind < numtxids )
    {
        *txidp = T[ind].txid;
        return(s->prevout);
    }
    return(-2);
}

int32_t iguana_ramchain_txid(struct iguana_info *coin,RAMCHAIN_FUNC,bits256 *txidp,struct iguana_spend *s)
{
    uint32_t ind,external;
    memset(txidp,0,sizeof(*txidp));
    //printf("s.%p ramchaintxid vout.%x spendtxidind.%d numexternals.%d isext.%d numspendinds.%d\n",s,s->vout,s->spendtxidind,ramchain->numexternaltxids,s->external,ramchain->numspends);
    if ( s->prevout < 0 )
        return(-1);
    ind = s->spendtxidind;
    external = (ind >> 31) & 1;
    ind &= ~(1 << 31);
    if ( s->external != 0 && s->external == external && ind < ramchain->H.data->numexternaltxids )
    {
        //printf("ind.%d externalind.%d X[%d]\n",ind,ramchain->externalind,ramchain->H.data->numexternaltxids);
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

uint32_t iguana_ramchain_addspend(struct iguana_info *coin,RAMCHAIN_FUNC,bits256 prev_hash,int32_t prev_vout,uint32_t sequence)//,int32_t hdrsi,int32_t bundlei)
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
        if ( 0 && ramchain->expanded != 0 )
            { char str[65]; printf("%p X[%d] <- %s\n",X,txidind,bits256_str(str,prev_hash)); }
        if ( ramchain->H.ROflag != 0 )
        {
            if ( memcmp(X[txidind].bytes,prev_hash.bytes,sizeof(prev_hash)) != 0 )
            {
                char str[65],str2[65]; printf("iguana_ramchain_addspend X[%d] of %d cmperror %s vs %s\n",txidind,ramchain->H.data->numexternaltxids,bits256_str(str,X[txidind]),bits256_str(str2,prev_hash));
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
        } else printf("addspend illegal txidind.%d vs %d\n",txidind,ramchain->H.data->numtxids), exit(-1);
    }
    if ( ramchain->H.ROflag != 0 )
    {
        iguana_ramchain_txid(coin,RAMCHAIN_ARG,&txid,s);
        if ( (s->diffsequence == 0 && sequence != 0xffffffff) || (s->diffsequence != 0 && sequence == 0xffffffff) || memcmp(txid.bytes,prev_hash.bytes,sizeof(bits256)) != 0 || s->prevout != prev_vout )// || s->hdrsi != hdrsi
        {
            char str[65],str2[65]; printf("ramchain_addspend RO value mismatch diffseq.%d v %x (%d) vs (%d) %s vs %s\n",s->diffsequence,sequence,s->prevout,prev_vout,bits256_str(str,txid),bits256_str(str2,prev_hash));
            return(0);
        }
    }
    else
    {
        if ( sequence != 0xffffffff )
            s->diffsequence = 1;
        s->external = external, s->spendtxidind = txidind,
        s->prevout = prev_vout;
        //s->hdrsi = hdrsi;
        //s->bundlei = bundlei;
        //char str[65]; printf("%s set prevout.%d -> %d\n",bits256_str(str,prev_hash),prev_vout,s->prevout);
        //if ( pkind != 0 )
        //    s->prevspendind = A[pkind].lastspendind;
    }
    if ( pkind != 0 )
    {
        A[pkind].balance -= value;
        //A[pkind].lastspendind = spendind;
        //if ( P2[pkind].firstspendind == 0 )
        //    P2[pkind].firstspendind = spendind;
    }
    /*if ( unspentind != 0 )
    {
        if ( U2[unspentind].spendind == 0 )
            U2[unspentind].spendind = spendind;
    }*/
    return(spendind);
}

int64_t iguana_hashmemsize(uint32_t numtxids,uint32_t numunspents,uint32_t numspends,uint32_t numpkinds,uint32_t numexternaltxids)
{
    int64_t allocsize = 0;
    allocsize += (65536*4 + ((numtxids + numpkinds) * (sizeof(UT_hash_handle)*2)) + (((sizeof(struct iguana_account)) * 2 * numpkinds)) + (2 * numunspents * sizeof(struct iguana_Uextra)));
    //printf("iguana_hashmemsize T.%d U.%d S.%d P.%d X.%d -> %ld\n",numtxids,numunspents,numspends,numpkinds,numexternaltxids,(long)allocsize);
    return(allocsize);
}

void _iguana_ramchain_setptrs(RAMCHAIN_PTRPS,struct iguana_ramchaindata *rdata)
{
    *B = (void *)((long)rdata + (long)rdata->Boffset);
    *T = (void *)((long)rdata + (long)rdata->Toffset);
    if ( ramchain->expanded != 0 )
    {
        *Ux = (void *)((long)rdata + (long)rdata->Uoffset);
        *Sx = (void *)((long)rdata + (long)rdata->Soffset);
        *P = (void *)((long)rdata + (long)rdata->Poffset);
        *X = (void *)((long)rdata + (long)rdata->Xoffset);
        //ramchain->roU2 = (void *)((long)rdata + (long)rdata->U2offset);
        //ramchain->roP2 = (void *)((long)rdata + (long)rdata->P2offset);
        ramchain->roA = (void *)((long)rdata + (long)rdata->Aoffset);
        //if ( (*U2= ramchain->U2) == 0 )
        //    *U2 = ramchain->U2 = ramchain->roU2;
        //if ( (*P2= ramchain->P2) == 0 )
        //    *P2 = ramchain->P2 = ramchain->roP2;
        if ( (*A= ramchain->A) == 0 )
            *A = ramchain->A = ramchain->roA;
        //printf("T.%p Ux.%p Sx.%p P.%p\n",*T,*Ux,*Sx,*P);
        *TXbits = (void *)((long)rdata + (long)rdata->TXoffset);
        *PKbits = (void *)((long)rdata + (long)rdata->PKoffset);
        *U = 0, *S = 0;
    }
    else
    {
        *U = (void *)((long)rdata + (long)rdata->Uoffset);
        *S = (void *)((long)rdata + (long)rdata->Soffset);
        *Ux = 0, *Sx = 0, *P = 0, *X = 0, *A = 0, *TXbits = 0, *PKbits = 0; //*U2 = 0, *P2 = 0,
    }
}

void *iguana_ramchain_offset(void *dest,uint8_t *lhash,FILE *fp,uint64_t fpos,void *srcptr,uint64_t *offsetp,uint64_t len,uint64_t srcsize)
{
    void *destptr = (void *)((long)dest + *offsetp);
    if ( (lhash != 0 || fp != 0) && (*offsetp + len) > srcsize )
    {
        printf("ramchain_offset overflow (%p %p) offset.%ld + len.%ld %ld > %ld srcsize\n",fp,lhash,(long)*offsetp,(long)len,(long)(*offsetp + len),(long)srcsize);
        exit(-1);
    }
    if ( lhash != 0 )
    {
        //fprintf(stderr,"lhash.%p memptr.%p offset.%ld len.%ld avail.%ld srcsize.%ld\n",lhash,srcptr,(long)*offsetp,(long)len,(long)(srcsize - (*offsetp + len)),(long)srcsize);
        vcalc_sha256(0,lhash,srcptr,(uint32_t)len);
    }
    else if ( fp != 0 )
    {
        if ( fwrite(srcptr,1,len,fp) != len )
            printf("iguana_ramchain_sizefunc: error writing len.%ld to fp.%p\n",(long)len,fp);
        //else printf("fp.(%ld <- %d) ",ftell(fp),(int32_t)len);
    }
    (*offsetp) += len;
    return((void *)((long)destptr + fpos));
}

int64_t _iguana_rdata_action(FILE *fp,bits256 lhashes[IGUANA_NUMLHASHES],void *destptr,uint64_t fpos,uint32_t expanded,uint32_t numtxids,uint32_t numunspents,uint32_t numspends,uint32_t numpkinds,uint32_t numexternaltxids,uint32_t txsparsebits,uint64_t numtxsparse,uint32_t pksparsebits,uint64_t numpksparse,uint64_t srcsize,RAMCHAIN_FUNC,int32_t numblocks)
{
#define RAMCHAIN_LARG(ind) ((lhashes == 0) ? 0 : lhashes[ind].bytes)
#define SPARSECOUNT(x) ((x) << 2)
    FILE *fparg = 0; int32_t iter; uint64_t txbits,pkbits,offset = 0; struct iguana_ramchaindata *rdata = destptr;
    if ( expanded != 0 )
    {
        if( txsparsebits == 0 || numtxsparse == 0 )
        {
            txsparsebits = hcalc_bitsize(numtxids);
            numtxsparse = SPARSECOUNT(numtxids);
        }
        if ( pksparsebits == 0 || numpksparse == 0 )
        {
            pksparsebits = hcalc_bitsize(numpkinds);
            numpksparse = SPARSECOUNT(numpkinds);
        }
        txbits = numtxsparse * txsparsebits; pkbits = numpksparse * pksparsebits;
    } else txbits = pkbits = numtxsparse = txsparsebits = numpksparse = pksparsebits = 0;
    for (iter=0; iter<2; iter++)
    {
        if ( iter == 0 && lhashes == 0 )
        {
            fparg = fp;
            continue;
        }
        offset = sizeof(struct iguana_ramchaindata);
        B = iguana_ramchain_offset(rdata,RAMCHAIN_LARG(IGUANA_LHASH_BLOCKS),fparg,fpos,B,&offset,(sizeof(struct iguana_blockRO) * numblocks),srcsize);
        T = iguana_ramchain_offset(rdata,RAMCHAIN_LARG(IGUANA_LHASH_TXIDS),fparg,fpos,T,&offset,(sizeof(struct iguana_txid) * numtxids),srcsize);
        if ( expanded != 0 )
        {
            U = destptr, S = destptr;
            Ux = iguana_ramchain_offset(rdata,RAMCHAIN_LARG(IGUANA_LHASH_UNSPENTS),fparg,fpos,Ux,&offset,(sizeof(struct iguana_unspent) * numunspents),srcsize);
            Sx = iguana_ramchain_offset(rdata,RAMCHAIN_LARG(IGUANA_LHASH_SPENDS),fparg,fpos,Sx,&offset,(sizeof(struct iguana_spend) * numspends),srcsize);
            P = iguana_ramchain_offset(rdata,RAMCHAIN_LARG(IGUANA_LHASH_PKHASHES),fparg,fpos,P,&offset,(sizeof(struct iguana_pkhash) * numpkinds),srcsize);
            //U2 = iguana_ramchain_offset(rdata,RAMCHAIN_LARG(IGUANA_LHASH_SPENTINDS),fparg,fpos,U2,&offset,(sizeof(struct iguana_Uextra) * numunspents),srcsize);
            //P2 = 0;//iguana_ramchain_offset(rdata,RAMCHAIN_LARG(IGUANA_LHASH_FIRSTSPENDS),fparg,fpos,P2,&offset,(sizeof(struct iguana_pkextra) * numpkinds),srcsize);
            A = iguana_ramchain_offset(rdata,RAMCHAIN_LARG(IGUANA_LHASH_ACCOUNTS),fparg,fpos,A,&offset,(sizeof(struct iguana_account) * numpkinds),srcsize);
            char str[65];
            if ( 0 && X != 0 )
                printf("%p X[1] -> %s\n",&X[1],bits256_str(str,X[1]));
            X = iguana_ramchain_offset(rdata,RAMCHAIN_LARG(IGUANA_LHASH_EXTERNALS),fparg,fpos,X,&offset,(sizeof(bits256) * numexternaltxids),srcsize);
            TXbits = iguana_ramchain_offset(rdata,RAMCHAIN_LARG(IGUANA_LHASH_TXBITS),fparg,fpos,TXbits,&offset,hconv_bitlen(txbits),srcsize);
            PKbits = iguana_ramchain_offset(rdata,RAMCHAIN_LARG(IGUANA_LHASH_PKBITS),fparg,fpos,PKbits,&offset,hconv_bitlen(pkbits),srcsize);
        }
        else
        {
            Ux = destptr, Sx = destptr, P = destptr, A = destptr, X = destptr, TXbits = destptr, PKbits = destptr; //U2 = destptr, P2 = destptr,
            U = iguana_ramchain_offset(rdata,RAMCHAIN_LARG(IGUANA_LHASH_UNSPENTS),fparg,fpos,U,&offset,(sizeof(struct iguana_unspent20) * numunspents),srcsize);
            if ( 0 && lhashes != 0 )
                printf("iter.%d lhashes.%p offset.%ld destptr.%p len.%ld fparg.%p fpos.%ld srcsize.%ld\n",iter,RAMCHAIN_LARG(IGUANA_LHASH_SPENDS),(long)offset,destptr,(long)sizeof(struct iguana_spend256) * numspends,fparg,(long)fpos,(long)srcsize);
            S = iguana_ramchain_offset(rdata,RAMCHAIN_LARG(IGUANA_LHASH_SPENDS),fparg,fpos,S,&offset,(sizeof(struct iguana_spend256) * numspends),srcsize);
        }
        if ( (fparg= fp) == 0 )
            break;
        lhashes = 0;
    }
    if ( rdata != 0 )
    {
        rdata->allocsize = offset;
        rdata->Boffset = (uint64_t)((long)B - (long)destptr);
        rdata->Toffset = (uint64_t)((long)T - (long)destptr);
        if ( expanded != 0 )
        {
            rdata->Uoffset = (uint64_t)((long)Ux - (long)destptr);
            rdata->Soffset = (uint64_t)((long)Sx - (long)destptr);
        }
        else
        {
            rdata->Uoffset = (uint64_t)((long)U - (long)destptr);
            rdata->Soffset = (uint64_t)((long)S - (long)destptr);
        }
        rdata->Poffset = (uint64_t)((long)P - (long)destptr);
        //rdata->U2offset = (uint64_t)((long)U2 - (long)destptr);
        //rdata->P2offset = (uint64_t)((long)P2 - (long)destptr);
        rdata->Aoffset = (uint64_t)((long)A - (long)destptr);
        rdata->Xoffset = (uint64_t)((long)X - (long)destptr);
        rdata->TXoffset = (uint64_t)((long)TXbits - (long)destptr);
        rdata->PKoffset = (uint64_t)((long)PKbits - (long)destptr);
        rdata->numtxids = numtxids;
        rdata->numunspents = numunspents;
        rdata->numspends = numspends;
        rdata->numpkinds = numpkinds;
        rdata->numexternaltxids = numexternaltxids;
        rdata->txsparsebits = txsparsebits, rdata->numtxsparse = (uint32_t)numtxsparse;
        rdata->pksparsebits = pksparsebits, rdata->numpksparse = (uint32_t)numpksparse;
    }
    return(offset);
#undef RAMCHAIN_LARG
#undef SPARSECOUNT
}

int64_t iguana_ramchain_action(RAMCHAIN_FUNC,FILE *fp,bits256 lhashes[IGUANA_NUMLHASHES],struct iguana_ramchaindata *destdata,uint64_t fpos,struct iguana_ramchaindata *srcdata,int32_t numblocks)
{
    if ( 0 && ramchain->expanded != 0 )
        printf("action.%p (%p %p %p) %ld allocated.%ld [%d:%d %d:%d]\n",srcdata,fp,lhashes,destdata,(long)fpos,(long)srcdata->allocsize,srcdata->txsparsebits,srcdata->numtxsparse,srcdata->pksparsebits,srcdata->numpksparse);
    return(_iguana_rdata_action(fp,lhashes,destdata,fpos,ramchain->expanded,srcdata->numtxids,srcdata->numunspents,srcdata->numspends,srcdata->numpkinds,srcdata->numexternaltxids,srcdata->txsparsebits,srcdata->numtxsparse,srcdata->pksparsebits,srcdata->numpksparse,srcdata->allocsize,RAMCHAIN_ARG,numblocks));
}

int64_t iguana_ramchain_size(RAMCHAIN_FUNC,int32_t numblocks)
{
    return(iguana_ramchain_action(RAMCHAIN_ARG,0,0,0,0,ramchain->H.data,numblocks));
}

long iguana_ramchain_setsize(struct iguana_ramchain *ramchain,struct iguana_ramchaindata *srcdata,int32_t numblocks)
{
    RAMCHAIN_DECLARE; struct iguana_ramchaindata *rdata = ramchain->H.data;
    B = 0, Ux = 0, Sx = 0, P = 0, A = 0, X = 0, TXbits = 0, PKbits = 0, U = 0, S = 0, T = 0; //U2 = 0, P2 = 0,
    rdata->numtxids = ramchain->H.txidind;
    rdata->numunspents = ramchain->H.unspentind;
    rdata->numspends = ramchain->H.spendind;
    rdata->numpkinds = ramchain->pkind;
    rdata->numexternaltxids = ramchain->externalind;
    rdata->allocsize = iguana_ramchain_size(RAMCHAIN_ARG,numblocks);
    ramchain->datasize = rdata->allocsize;
    return((long)rdata->allocsize);
}

int64_t iguana_ramchain_compact(RAMCHAIN_FUNC,struct iguana_ramchaindata *destdata,struct iguana_ramchaindata *srcdata,int32_t numblocks)
{
    //iguana_ramchain_setsize(ramchain,srcdata);
    return(iguana_ramchain_action(RAMCHAIN_ARG,0,0,destdata,0,srcdata,numblocks));
}

bits256 iguana_ramchain_lhashes(RAMCHAIN_FUNC,struct iguana_ramchaindata *destdata,struct iguana_ramchaindata *srcdata,int32_t numblocks)
{
    iguana_ramchain_action(RAMCHAIN_ARG,0,destdata->lhashes,0,0,srcdata,numblocks);
    memset(&destdata->sha256,0,sizeof(destdata->sha256));
    vcalc_sha256(0,destdata->sha256.bytes,(void *)destdata,sizeof(*destdata));
    return(destdata->sha256);
}

int64_t iguana_ramchain_saveaction(RAMCHAIN_FUNC,FILE *fp,struct iguana_ramchaindata *rdata,int32_t numblocks)
{
    long before,after;
    before = ftell(fp);
    iguana_ramchain_action(RAMCHAIN_ARG,fp,0,rdata,0,rdata,numblocks);
    after = ftell(fp);
    if ( 0 && ramchain->expanded != 0 )
    {
        char str[65];
        printf("SAVEACTION: rdata.%ld DEST T.%d U.%d S.%d P.%d X.%d -> size.%ld %ld vs %ld %p %s\n",sizeof(*rdata),rdata->numtxids,rdata->numunspents,rdata->numspends,rdata->numpkinds,rdata->numexternaltxids,(long)rdata->allocsize,(long)iguana_ramchain_size(RAMCHAIN_ARG,numblocks),after-before+sizeof(*rdata),&X[1],bits256_str(str,X[1]));
    }
    //printf("before.%ld after.%ld allocsize.%ld [%ld] %ld expanded.%d\n",before,after,(long)srcdata->allocsize,(long)ramchain->H.data->allocsize,(long)iguana_ramchain_size(ramchain),ramchain->expanded);
    return(after - before);
}

int64_t iguana_ramchain_init(struct iguana_ramchain *ramchain,struct OS_memspace *mem,struct OS_memspace *hashmem,int32_t firsti,int32_t numtxids,int32_t numunspents,int32_t numspends,int32_t numpkinds,int32_t numexternaltxids,int32_t expanded,int32_t numblocks)
{
    RAMCHAIN_DECLARE; int64_t offset = 0; struct iguana_ramchaindata *rdata;
    B = 0, Ux = 0, Sx = 0, P = 0, A = 0, X = 0, TXbits = 0, PKbits = 0, U = 0, S = 0, T = 0; //U2 = 0, P2 = 0,
    if ( mem == 0 )
        return(0);
    memset(ramchain,0,sizeof(*ramchain));
    ramchain->expanded = (expanded != 0);
    if ( (ramchain->hashmem= hashmem) != 0 )
        iguana_memreset(hashmem);
    rdata = ramchain->H.data = mem->ptr, offset += sizeof(struct iguana_ramchaindata);
    if ( (rdata->firsti= firsti) != 0 )
    {
        numtxids++, numunspents++, numspends++;
        if ( numpkinds != 0 )
            numpkinds++;
    }
    if ( numexternaltxids == 0 )
        numexternaltxids = numspends;
    if ( numpkinds == 0 )
        numpkinds = numunspents;
    if ( 0 && expanded != 0 )
        printf("init T.%d U.%d S.%d P.%d X.%d -> %ld\n",numtxids,numunspents,numspends,numpkinds,numexternaltxids,(long)offset);
    _iguana_rdata_action(0,0,rdata,0,expanded,numtxids,numunspents,numspends,numpkinds,numexternaltxids,0,0,0,0,0,RAMCHAIN_ARG,numblocks);
    if ( rdata->allocsize != iguana_ramchain_size(RAMCHAIN_ARG,numblocks) )
    {
        printf("offset.%ld vs memsize.%ld\n",(long)offset,(long)iguana_ramchain_size(RAMCHAIN_ARG,numblocks));
        exit(-1);
    }
    if ( offset < mem->totalsize )
        iguana_memreset(mem);
    else
    {
        printf("offset.%ld vs memsize.%ld\n",(long)offset,(long)iguana_ramchain_size(RAMCHAIN_ARG,numblocks));
        printf("NEED %ld realloc for %ld\n",(long)offset,(long)mem->totalsize);
        exit(-1);
        iguana_mempurge(mem);
        iguana_meminit(mem,"ramchain",0,offset,0);
    }
    //printf("init.(%d %d %d %d %d)\n",numtxids,numunspents,numspends,numpkinds,numexternaltxids);
    return(offset);
}

int32_t iguana_ramchain_alloc(struct iguana_info *coin,struct iguana_ramchain *ramchain,struct OS_memspace *mem,struct OS_memspace *hashmem,uint32_t numtxids,uint32_t numunspents,uint32_t numspends,uint32_t numpkinds,uint32_t numexternaltxids,int32_t height,int32_t numblocks)
{
    RAMCHAIN_DECLARE; int64_t hashsize,allocsize,x;
    B = 0, Ux = 0, Sx = 0, P = 0, A = 0, X = 0, TXbits = 0, PKbits = 0, U = 0, S = 0, T = 0; //U2 = 0, P2 = 0,
    memset(ramchain,0,sizeof(*ramchain));
    ramchain->height = height;
    allocsize = _iguana_rdata_action(0,0,0,0,1,numtxids,numunspents,numspends,numpkinds,numexternaltxids,0,0,0,0,0,RAMCHAIN_ARG,numblocks);
    //printf("T.%d U.%d S.%d P.%d X.%d -> %ld\n",numtxids,numunspents,numspends,numpkinds,numexternaltxids,(long)allocsize);
    memset(mem,0,sizeof(*mem));
    memset(hashmem,0,sizeof(*hashmem));
    hashsize = iguana_hashmemsize(numtxids,numunspents,numspends,numpkinds,numexternaltxids);
    while ( (x= (myallocated(0,-1)+hashsize+allocsize)) > coin->MAXMEM )
    {
        char str[65],str2[65]; fprintf(stderr,"ht.%d wait for allocated %s < MAXMEM %s | elapsed %.2f minutes\n",height,mbstr(str,hashsize+allocsize),mbstr(str2,coin->MAXMEM),(double)(time(NULL)-coin->startutc)/60.);
        sleep(3);
    }
    iguana_meminit(hashmem,"ramhashmem",0,hashsize + 4096,0);
    iguana_meminit(mem,"ramchain",0,allocsize + 4096,0);
    mem->alignflag = sizeof(uint32_t);
    hashmem->alignflag = sizeof(uint32_t);
    if ( iguana_ramchain_init(ramchain,mem,hashmem,1,numtxids,numunspents,numspends,numpkinds,numexternaltxids,1,numblocks) == 0 )
        return(-1);
    return(0);
}

long iguana_ramchain_save(struct iguana_info *coin,RAMCHAIN_FUNC,uint32_t ipbits,bits256 hash2,bits256 prevhash2,int32_t bundlei,struct iguana_bundle *bp)
{
    struct iguana_ramchaindata *rdata,tmp;
    char fname[1024]; long fpos = -1; int32_t hdrsi,checki; FILE *fp;
    if ( (rdata= ramchain->H.data) == 0 )
    {
        printf("ramchainsave no data ptr\n");
        return(-1);
    }
    if ( (checki= iguana_peerfname(coin,&hdrsi,ipbits==0?"DB":"tmp",fname,ipbits,hash2,prevhash2,ramchain->numblocks)) != bundlei || bundlei < 0 || bundlei >= coin->chain->bundlesize )
    {
        printf(" wont save.(%s) bundlei.%d != checki.%d\n",fname,bundlei,checki);
        return(-1);
    }
    OS_compatible_path(fname);
    if ( (fp= fopen(fname,"rb+")) == 0 )
    {
        if ( (fp= fopen(fname,"wb")) != 0 )
            coin->peers.numfiles++;
    }
    else if ( ipbits != 0 )
        fseek(fp,0,SEEK_END);
    else
    {
        fclose(fp);
        fp = fopen(fname,"wb");
    }
    if ( fp != 0 )
    {
        fpos = ftell(fp);
        iguana_ramchain_lhashes(RAMCHAIN_ARG,rdata,rdata,bp!=0?bp->n:1);
        tmp = *rdata;
        iguana_ramchain_compact(RAMCHAIN_ARG,&tmp,rdata,bp!=0?bp->n:1);
        fwrite(&tmp,1,sizeof(tmp),fp);
        iguana_ramchain_saveaction(RAMCHAIN_ARG,fp,rdata,bp!=0?bp->n:1);
        *rdata = tmp;
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
    _iguana_ramchain_setptrs(RAMCHAIN_PTRS,rdata);
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
            exit(-1);
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
            {
                if ( strcmp(coin->symbol,"BTC") == 0 )
                {
                    bits256 duptxid,duptxid2;
                decode_hex(duptxid.bytes,sizeof(duptxid),"e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468"); // BTC.tx0: 91722, 91880
                    decode_hex(duptxid2.bytes,sizeof(duptxid2),"d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599"); // BTC.tx0 91812, 91842
                    if ( memcmp(duptxid.bytes,t->txid.bytes,sizeof(duptxid)) == 0 || memcmp(duptxid2.bytes,t->txid.bytes,sizeof(duptxid2)) == 0 )
                        printf("BIP 0 detected\n");
                    else
                    {
                        char str[65]; printf("error -3: %s itemind.%d vs txidind.%d | num.%d\n",bits256_str(str,t->txid),ptr->hh.itemind,ramchain->H.txidind,ramchain->H.data->numtxids);
                        return(-3);
                    }
                }
                else
                {
                    char str[65]; printf("error -3: %s itemind.%d vs txidind.%d | num.%d\n",bits256_str(str,t->txid),ptr->hh.itemind,ramchain->H.txidind,ramchain->H.data->numtxids);
                    exit(-1);
                    return(-3);
                }
            }
            for (k=0; k<t->numvouts; k++,ramchain->H.unspentind++)
            {
                u = &Ux[ramchain->H.unspentind];
                if ( u->txidind != ramchain->H.txidind )
                {
                    printf("ramchain_verify k.%d %p U.%d u->txidind.%x != txidind.%d\n",k,u,ramchain->H.unspentind,u->txidind,ramchain->H.txidind);
                    exit(-1);
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
            {
                printf("k.%d balance.(%.8f vs %.8f) lastU.(%d %d)\n",k,dstr(ramchain->A[k].balance),dstr(ramchain->roA[k].balance),ramchain->A[k].lastunspentind,ramchain->roA[k].lastunspentind);
                return(-14);
            }
            //if ( memcmp(&ramchain->P2[k],&ramchain->roP2[k],sizeof(ramchain->P2[k])) != 0 )
            //    return(-15);
        }
        //for (k=rdata->firsti; k<rdata->numunspents; k++)
        //    if ( memcmp(&ramchain->U2[k],&ramchain->roU2[k],sizeof(ramchain->U2[k])) != 0 )
        //        return(-16);
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
        //if ( ramchain->U2 != ramchain->roU2 )
        //    myfree(ramchain->U2,sizeof(*ramchain->U2) * ramchain->H.data->numunspents), ramchain->U2 = 0;
        //if ( ramchain->P2 != ramchain->roP2 )
        //    myfree(ramchain->P2,sizeof(*ramchain->P2) * ramchain->H.data->numpkinds), ramchain->P2 = 0;
    }
    if ( deleteflag != 0 )
    {
        if ( ramchain->txids != 0 )
        {
            HASH_ITER(hh,ramchain->txids,item,tmp)
            {
                HASH_DEL(ramchain->txids,item);
                if ( ramchain->hashmem == 0 )
                    myfree(item,sizeof(*item));
            }
        }
        if ( ramchain->pkhashes != 0 )
        {
            HASH_ITER(hh,ramchain->pkhashes,item,tmp)
            {
                HASH_DEL(ramchain->pkhashes,item);
                if ( ramchain->hashmem == 0 )
                    myfree(item,sizeof(*item));
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

void iguana_ramchain_extras(struct iguana_ramchain *ramchain,struct OS_memspace *hashmem)
{
    RAMCHAIN_DECLARE;
    if ( ramchain->expanded != 0 )
    {
        _iguana_ramchain_setptrs(RAMCHAIN_PTRS,ramchain->H.data);
        if ( (ramchain->hashmem= hashmem) != 0 )
            iguana_memreset(hashmem);
        ramchain->A = (hashmem != 0) ? iguana_memalloc(hashmem,sizeof(struct iguana_account) * ramchain->H.data->numpkinds,1) : mycalloc('p',ramchain->H.data->numpkinds,sizeof(struct iguana_account));
        //ramchain->P2 = (hashmem != 0) ? iguana_memalloc(hashmem,sizeof(struct iguana_pkextra) * ramchain->H.data->numpkinds,1) : mycalloc('2',ramchain->H.data->numpkinds,sizeof(struct iguana_pkextra));
        ///ramchain->U2 = (hashmem != 0) ? iguana_memalloc(hashmem,sizeof(struct iguana_Uextra) * ramchain->H.data->numunspents,1) : mycalloc('3',ramchain->H.data->numunspents,sizeof(struct iguana_Uextra));
        //printf("iguana_ramchain_extras A.%p:%p U2.%p:%p P2.%p:%p\n",ramchain->A,ramchain->roA,ramchain->U2,ramchain->roU2,ramchain->P2,ramchain->roP2);
        //memcpy(ramchain->U2,ramchain->roU2,sizeof(*ramchain->U2) * ramchain->H.data->numunspents);
        //memcpy(ramchain->P2,ramchain->roP2,sizeof(*ramchain->P2) * ramchain->H.data->numpkinds);
    }
}

struct iguana_ramchain *iguana_ramchain_map(struct iguana_info *coin,char *fname,struct iguana_bundle *bp,int32_t numblocks,struct iguana_ramchain *ramchain,struct OS_memspace *hashmem,uint32_t ipbits,bits256 hash2,bits256 prevhash2,int32_t bundlei,long fpos,int32_t allocextras,int32_t expanded)
{
    RAMCHAIN_DECLARE; int32_t valid,i,checki,hdrsi;
    char str[65],str2[65]; long filesize; void *ptr; struct iguana_block *block;
    if ( ramchain->fileptr == 0 || ramchain->filesize <= 0 )
    {
        if ( (checki= iguana_peerfname(coin,&hdrsi,ipbits==0?"DB":"tmp",fname,ipbits,hash2,prevhash2,numblocks)) != bundlei || bundlei < 0 || bundlei >= coin->chain->bundlesize )
        {
            printf("iguana_ramchain_map.(%s) illegal hdrsi.%d bundlei.%d %s\n",fname,hdrsi,bundlei,bits256_str(str,hash2));
            return(0);
        }
        memset(ramchain,0,sizeof(*ramchain));
        if ( (ptr= OS_mapfile(fname,&filesize,0)) == 0 )
            return(0);
        ramchain->fileptr = ptr;
        ramchain->filesize = (long)filesize;
        if ( (ramchain->hashmem= hashmem) != 0 )
            iguana_memreset(hashmem);
    }
    if ( ramchain->fileptr != 0 && ramchain->filesize > 0 )
    {
        // verify hashes
        ramchain->H.data = (void *)((long)ramchain->fileptr + fpos);
        ramchain->H.ROflag = 1;
        ramchain->expanded = expanded;
        ramchain->numblocks = (bp == 0) ? 1 : bp->n;
        //printf("ptr.%p %p mapped P[%d] fpos.%d + %ld -> %ld vs %ld\n",ptr,ramchain->H.data,(int32_t)ramchain->H.data->Poffset,(int32_t)fpos,(long)ramchain->H.data->allocsize,(long)(fpos + ramchain->H.data->allocsize),ramchain->filesize);
        if ( 0 && bp != 0 )
        {
            /*blocksRO = (struct iguana_blockRO *)ramchain->H.data;
            for (i=0; i<bp->n; i++)
            {
                printf("%p ",&blocksRO[i]);
                bp->hashes[i] = blocksRO[i].hash2;
                if ( (bp->blocks[i]= iguana_blockhashset(coin,-1,blocksRO[i].hash2,1)) == 0 )
             {
             printf("Error getting blockptr\n");
             return(0);
             }
             bp->blocks[i]->RO = blocksRO[i];
             }
             ramchain->H.data = (void *)&blocksRO[bp->n];*/
             for (valid=0,i=bp->n=1; i>=0; i--)
            {
                if ( (block= bp->blocks[i]) != 0 )
                {
                    if ( memcmp(block->RO.hash2.bytes,bp->hashes[i].bytes,sizeof(block->RO.hash2)) == 0 )
                    {
                        if ( i == 0 || memcmp(block->RO.prev_block.bytes,bp->hashes[i-1].bytes,sizeof(block->RO.prev_block)) == 0 )
                            valid++;
                    }
                }
            }
            if ( valid != bp->n )
            {
                printf("valid.%d != bp->n.%d, reject mapped ramchain\n",valid,bp->n);
                return(0);
            }
        }
        _iguana_ramchain_setptrs(RAMCHAIN_PTRS,ramchain->H.data);
        if ( iguana_ramchain_size(RAMCHAIN_ARG,ramchain->numblocks) != ramchain->H.data->allocsize || fpos+ramchain->H.data->allocsize > filesize )
        {
            printf("iguana_ramchain_map.(%s) size mismatch %ld vs %ld vs filesize.%ld numblocks.%d expanded.%d fpos.%d sum %ld\n",fname,(long)iguana_ramchain_size(RAMCHAIN_ARG,ramchain->numblocks),(long)ramchain->H.data->allocsize,(long)filesize,ramchain->numblocks,expanded,(int32_t)fpos,(long)(fpos+ramchain->H.data->allocsize));
            exit(-1);
            //munmap(ramchain->fileptr,ramchain->filesize);
            return(0);
        }
        else if ( memcmp(hash2.bytes,ramchain->H.data->firsthash2.bytes,sizeof(bits256)) != 0 )
        {
            printf("iguana_ramchain_map.(%s) hash2 mismatch %s vs %s\n",fname,bits256_str(str,hash2),bits256_str(str2,ramchain->H.data->firsthash2));
            //munmap(ramchain->fileptr,ramchain->filesize);
            return(0);
        }
        else if ( ramchain->expanded != 0 )
        {
            if ( allocextras > 0 )
                iguana_ramchain_extras(ramchain,ramchain->hashmem);
        }
        if ( B != 0 )
        {
            for (i=0; i<bp->n; i++)
            {
                if ( (bp->blocks[i]= iguana_blockhashset(coin,-1,B[i].hash2,1)) == 0 )
                {
                    printf("Error getting blockptr\n");
                    return(0);
                }
                bp->blocks[i]->RO = B[i];//coin->blocks.RO[bp->bundleheight + i];
                coin->blocks.RO[bp->bundleheight+i] = B[i];
            }
            
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
    ramchain->lasthash2 = lasthash2;
    ramchain->H.txidind = ramchain->H.unspentind = ramchain->H.spendind = ramchain->pkind = firsti;
    ramchain->externalind = 0;
}

int32_t iguana_ramchain_cmp(struct iguana_ramchain *A,struct iguana_ramchain *B,int32_t deepflag)
{
    int32_t i; char str[65],str2[65];
    struct iguana_txid *Ta,*Tb; struct iguana_unspent20 *Ua,*Ub; struct iguana_spend256 *Sa,*Sb;
    struct iguana_pkhash *Pa,*Pb; bits256 *Xa,*Xb; struct iguana_blockRO *Ba,*Bb;
    struct iguana_account *ACCTa,*ACCTb; struct iguana_unspent *Uxa,*Uxb;
    struct iguana_spend *Sxa,*Sxb; uint8_t *TXbitsa,*TXbitsb,*PKbitsa,*PKbitsb;
    
    if ( A->H.data != 0 && B->H.data != 0 && A->H.data->numblocks == B->H.data->numblocks && memcmp(A->H.data->firsthash2.bytes,B->H.data->firsthash2.bytes,sizeof(A->H.data->firsthash2)) == 0 )
    {
        if ( A->H.data->firsti == B->H.data->firsti && A->H.data->numtxids == B->H.data->numtxids && A->H.data->numunspents == B->H.data->numunspents && A->H.data->numspends == B->H.data->numspends && A->H.data->numpkinds == B->H.data->numpkinds && A->H.data->numexternaltxids == B->H.data->numexternaltxids )
        {
            _iguana_ramchain_setptrs(A,&Ba,&Ta,&Ua,&Sa,&Pa,&ACCTa,&Xa,&Uxa,&Sxa,&TXbitsa,&PKbitsa,A->H.data);
            _iguana_ramchain_setptrs(B,&Bb,&Tb,&Ub,&Sb,&Pb,&ACCTb,&Xb,&Uxb,&Sxb,&TXbitsb,&PKbitsb,B->H.data);
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
                    //if ( memcmp(&U2a[i],&U2b[i],sizeof(U2a[i])) != 0 )
                    //    return(-5);
                }
                for (i=A->H.data->firsti; i<A->H.data->numpkinds; i++)
                {
                    //if ( memcmp(&P2a[i],&P2b[i],sizeof(P2a[i])) != 0 )
                    //    return(-6);
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
    int32_t j,hdrsi,prevout; uint32_t sequence,destspendind=0,desttxidind=0;
    bits256 prevhash; uint64_t value; uint8_t type;
    struct iguana_txid *tx; struct iguana_ramchaindata *rdata; uint8_t *rmd160; struct iguana_unspent *u;
    if ( dest != 0 )
        _iguana_ramchain_setptrs(RAMCHAIN_DESTPTRS,dest->H.data);
    _iguana_ramchain_setptrs(RAMCHAIN_PTRS,ramchain->H.data);
    if ( (rdata= ramchain->H.data) == 0 )
    {
        printf("iguana_ramchain_iterate cant iterate without data\n");
        return(-1);
    }
    ramchain->H.ROflag = 1;
    ramchain->H.unspentind = ramchain->H.spendind = ramchain->pkind = rdata->firsti;
    ramchain->externalind = 0;
    if ( dest != 0 )
    {
        desttxidind = dest->H.txidind;
        destspendind = dest->H.spendind;
    }
    for (ramchain->H.txidind=rdata->firsti; ramchain->H.txidind<rdata->numtxids; ramchain->H.txidind++)
    {
        if ( 0 && ramchain->expanded != 0 )
            printf("ITER TXID.%d -> dest.%p desttxid.%d dest->hashmem.%p\n",ramchain->H.txidind,dest,dest!=0?dest->H.txidind:0,dest!=0?dest->hashmem:0);
        tx = &T[ramchain->H.txidind];
        if ( iguana_ramchain_addtxid(coin,RAMCHAIN_ARG,tx->txid,tx->numvouts,tx->numvins,tx->locktime,tx->version,tx->timestamp) == 0 )
            return(-1);
        if ( dest != 0 )
        {
            char str[65];
            if ( 0 && ramchain->expanded != 0 )
                printf("add hdrsi.%d dest.%p txidind.%d %s\n",dest->H.hdrsi,ramchain,dest->H.txidind,bits256_str(str,tx->txid));
            if ( iguana_ramchain_addtxid(coin,RAMCHAIN_DESTARG,tx->txid,tx->numvouts,tx->numvins,tx->locktime,tx->version,tx->timestamp) == 0 )
                return(-2);
        }
        for (j=0; j<tx->numvouts; j++)
        {
            if ( 0 && ramchain->expanded != 0 )
                printf("unspentind.%d pkind.%d Ux.%p\n",ramchain->H.unspentind,Ux[ramchain->H.unspentind].pkind,Ux);
            if ( ramchain->H.unspentind < rdata->numunspents )
            {
                if ( ramchain->expanded != 0 )
                {
                    u = &Ux[ramchain->H.unspentind];
                    value = u->value;
                    hdrsi = u->hdrsi;
                    type = u->type;
                    if ( u->pkind < rdata->numpkinds )
                    {
                        rmd160 = P[u->pkind].rmd160;
                        if ( iguana_ramchain_addunspent(coin,RAMCHAIN_ARG,value,hdrsi,rmd160,j,type) == 0 )
                            return(-3);
                    }
                }
                else
                {
                    hdrsi = rdata->hdrsi;
                    value = U[ramchain->H.unspentind].value;
                    rmd160 = U[ramchain->H.unspentind].rmd160;
                    type = U[ramchain->H.unspentind].type;
                    if ( iguana_ramchain_addunspent20(coin,RAMCHAIN_ARG,value,rmd160,-20,tx->txid,j,type) == 0 )
                        return(-4);
                }
                if ( dest != 0 )
                {
                    if ( iguana_ramchain_addunspent(coin,RAMCHAIN_DESTARG,value,hdrsi,rmd160,j,type) == 0 )
                        return(-5);
                }
            } else return(-6);
        }
        ramchain->H.spendind += tx->numvins;
        if ( dest != 0 )
        {
            dest->H.txidind++;
            dest->H.spendind += tx->numvins;
        }
    }
    if ( dest != 0 )
    {
        dest->H.txidind = desttxidind;
        dest->H.spendind = destspendind;
    }
    ramchain->H.txidind = ramchain->H.spendind = rdata->firsti;
    for (ramchain->H.txidind=rdata->firsti; ramchain->H.txidind<rdata->numtxids; ramchain->H.txidind++)
    {
        tx = &T[ramchain->H.txidind];
        for (j=0; j<tx->numvins; j++)
        {
            if ( ramchain->expanded != 0 )
            {
                sequence = (Sx[ramchain->H.spendind].diffsequence == 0) ? 0xffffffff : 0;
                prevout = iguana_ramchain_txid(coin,RAMCHAIN_ARG,&prevhash,&Sx[ramchain->H.spendind]);
                //bundlei = Sx[ramchain->H.spendind].bundlei;
                //hdrsi = Sx[ramchain->H.spendind].hdrsi;
                if ( iguana_ramchain_addspend(coin,RAMCHAIN_ARG,prevhash,prevout,sequence) == 0 )
                {
                    char str[65]; int32_t i;
                    printf("txidind.%d spendind.%d spendtxid.%x %d vin.%d %s vout.%d\n",ramchain->H.txidind,ramchain->H.spendind,Sx[ramchain->H.spendind].spendtxidind,Sx[ramchain->H.spendind].spendtxidind&0xfffffff,j,bits256_str(str,prevhash),prevout);
                    for (i=0; i<ramchain->H.data->numexternaltxids; i++)
                        printf("%p X[%d] %s\n",X,i,bits256_str(str,X[i]));
                    exit(-1);
                    iguana_ramchain_txid(coin,RAMCHAIN_ARG,&prevhash,&Sx[ramchain->H.spendind]);
                    return(-7);
                }
            }
            else
            {
                //spendind = (tx->firstvin + j);
                sequence = (S[ramchain->H.spendind].diffsequence == 0) ? 0xffffffff : 0;
                prevhash = S[ramchain->H.spendind].prevhash2;
                prevout = S[ramchain->H.spendind].prevout;
                //bundlei = S[ramchain->H.spendind].bundlei;
                //hdrsi = S[ramchain->H.spendind].hdrsi;
                if ( iguana_ramchain_addspend256(coin,RAMCHAIN_ARG,prevhash,prevout,0,0,sequence) == 0 )
                    return(-8);
            }
            if ( dest != 0 )
            {
                if ( iguana_ramchain_addspend(coin,RAMCHAIN_DESTARG,prevhash,prevout,sequence) == 0 )
                    return(-9);
            }
        }
        if ( dest != 0 )
            dest->H.txidind++;
    }
    return(0);
}

long iguana_ramchain_data(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_txblock *origtxdata,struct iguana_msgtx *txarray,int32_t txn_count,uint8_t *data,int32_t recvlen)
{
    int32_t verifyflag = 0;
    RAMCHAIN_DECLARE; long fsize; void *ptr; struct iguana_ramchain R,*mapchain,*ramchain = &addr->ramchain;
    struct iguana_msgtx *tx; int32_t i,j,fpos,firsti=1,err,flag,bundlei = -2; char fname[1024];
    struct iguana_bundle *bp = 0; struct iguana_block *block;
    if ( iguana_bundlefind(coin,&bp,&bundlei,origtxdata->block.RO.hash2) == 0 )
    {
        if ( iguana_bundlefind(coin,&bp,&bundlei,origtxdata->block.RO.prev_block) == 0 )
            return(-1);
        else if ( bundlei < coin->chain->bundlesize-1 )
            bundlei++;
        else
        {
            printf("error finding block\n");
            return(-1);
        }
    }
    if ( bits256_nonz(bp->hashes[bundlei]) == 0 )
        bp->hashes[bundlei] = origtxdata->block.RO.hash2;
    if ( (block= bp->blocks[bundlei]) == 0 )
    {
        //char str[65]; printf("%d:%d has no block ptr %s\n",bp->hdrsi,bundlei,bits256_str(str,bp->hashes[bundlei]));
        return(-1);
    }
    if ( block->fpipbits != 0 )
    {
        //printf("ramchaindata have %d:%d at %d\n",bp->hdrsi,bundlei,bp->fpos[bundlei]);
        return(block->fpos);
    }
    //SETBIT(bp->recv,bundlei);
    fpos = -1;
    //bp->recvlens[bundlei] = recvlen;
    //bp->firsttxidinds[bundlei] = firsti;
    if ( iguana_ramchain_init(ramchain,&addr->TXDATA,&addr->HASHMEM,1,txn_count,origtxdata->numunspents,origtxdata->numspends,0,0,0,1) == 0 )
        return(-1);
    iguana_ramchain_link(ramchain,origtxdata->block.RO.hash2,origtxdata->block.RO.hash2,bp->hdrsi,bp->bundleheight+bundlei,bundlei,1,firsti,0);
    _iguana_ramchain_setptrs(RAMCHAIN_PTRS,ramchain->H.data);
    if ( T == 0 || U == 0 || S == 0 )// P == 0//|| X == 0 || A == 0 || U2 == 0 || P2 == 0 )
    {
        printf("fatal error getting txdataptrs\n");
        return(-1);
    }
    for (i=0; i<txn_count; i++,ramchain->H.txidind++)
    {
        tx = &txarray[i];
        iguana_ramchain_addtxid(coin,RAMCHAIN_ARG,tx->txid,tx->tx_out,tx->tx_in,tx->lock_time,tx->version,tx->timestamp);
        for (j=0; j<tx->tx_out; j++)
        {
            iguana_ramchain_addunspent20(coin,RAMCHAIN_ARG,tx->vouts[j].value,tx->vouts[j].pk_script,tx->vouts[j].pk_scriptlen,tx->txid,j,0);
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
            iguana_ramchain_addspend256(coin,RAMCHAIN_ARG,tx->vins[j].prev_hash,tx->vins[j].prev_vout,tx->vins[j].script,tx->vins[j].scriptlen,tx->vins[j].sequence);//,bp->hdrsi,bundlei);
        }
    }
    //char str[65]; printf("before height.%d num.%d:%d T.%d U.%d S.%d P.%d X.%d %s\n",ramchain->height,ramchain->numblocks,ramchain->H.data->numblocks,ramchain->H.txidind,ramchain->H.unspentind,ramchain->H.spendind,ramchain->pkind,ramchain->externalind,bits256_str(str,ramchain->H.data->firsthash2));
    iguana_ramchain_setsize(ramchain,ramchain->H.data,1);
    flag = 0;
    if ( ramchain->H.txidind != ramchain->H.data->numtxids || ramchain->H.unspentind != ramchain->H.data->numunspents || ramchain->H.spendind != ramchain->H.data->numspends )
    {
        printf("error creating PT ramchain: ramchain->txidind %d != %d ramchain->data->numtxids || ramchain->unspentind %d != %d ramchain->data->numunspents || ramchain->spendind %d != %d ramchain->data->numspends\n",ramchain->H.txidind,ramchain->H.data->numtxids,ramchain->H.unspentind,ramchain->H.data->numunspents,ramchain->H.spendind,ramchain->H.data->numspends);
    }
    else
    {
        if ( (err= iguana_ramchain_verify(coin,ramchain)) == 0 )
        {
            if ( (fpos= (int32_t)iguana_ramchain_save(coin,RAMCHAIN_ARG,addr->ipbits,origtxdata->block.RO.hash2,origtxdata->block.RO.prev_block,bundlei,0)) >= 0 )
            {
                //printf("set fpos.%d\n",fpos);
                //bp->ipbits[bundlei] = addr->ipbits;
                origtxdata->datalen = (int32_t)ramchain->H.data->allocsize;
                ramchain->H.ROflag = 0;
                flag = 1;
                memset(&R,0,sizeof(R));
                if ( verifyflag != 0 && (mapchain= iguana_ramchain_map(coin,fname,0,1,&R,0,addr->ipbits,origtxdata->block.RO.hash2,origtxdata->block.RO.prev_block,bundlei,fpos,1,0)) != 0 )
                {
                    //printf("mapped Soffset.%ld\n",(long)mapchain->data->Soffset);
                    iguana_ramchain_link(&R,origtxdata->block.RO.hash2,origtxdata->block.RO.hash2,bp->hdrsi,bp->bundleheight+bundlei,bundlei,1,firsti,1);
                    if ( 0 ) // crashes unix
                    {
                        if ( (err= iguana_ramchain_cmp(ramchain,mapchain,0)) != 0 )
                            printf("error.%d comparing ramchains\n",err);
                        ptr = mapchain->fileptr; fsize = mapchain->filesize;
                        mapchain->fileptr = 0, mapchain->filesize = 0;
                        iguana_ramchain_free(mapchain,1);
                        memset(&R,0,sizeof(R));
                        R.H.data = (void *)((long)ptr + fpos), R.filesize = fsize;
                        iguana_ramchain_link(&R,origtxdata->block.RO.hash2,origtxdata->block.RO.hash2,bp->hdrsi,bp->bundleheight+bundlei,bundlei,1,firsti,1);
                    }
                    if ( (err= iguana_ramchain_cmp(ramchain,&R,0)) != 0 )
                    {
                        fpos = -1;
                        printf("error.%d comparing REMAP ramchains\n",err);
                    }
                    else
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
                if ( fpos >= 0 )
                    block->fpos = fpos, block->fpipbits = addr->ipbits;
            }
        } else printf("ramchain verification error.%d hdrsi.%d bundlei.%d\n",err,bp->hdrsi,bundlei);
    }
    ramchain->H.ROflag = 0;
    iguana_ramchain_free(ramchain,0);
    return(fpos);
}

// two passes to check data size

void iguana_ramchain_disp(struct iguana_ramchain *ramchain)
{
    RAMCHAIN_DECLARE; int32_t j; uint32_t txidind,unspentind,spendind; struct iguana_txid *tx; char str[65];
    _iguana_ramchain_setptrs(RAMCHAIN_PTRS,ramchain->H.data);
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
    static bits256 zero;
    int32_t j,bundlei,num,hdrsi,checki; struct iguana_block *block; uint32_t fpipbits; char fname[1024];
    for (bundlei=num=0; bundlei<bp->n; bundlei++)
    {
        if ( (block= bp->blocks[bundlei]) != 0 )
            fpipbits = block->fpipbits;
        else return(0);
        if ( num > 0 )
        {
            for (j=0; j<num; j++)
                if ( ipbits[j] == fpipbits )
                    break;
        } else j = 0;
        if ( j == num )
        {
            ipbits[num] = fpipbits;
            if ( (checki= iguana_peerfname(coin,&hdrsi,"tmp",fname,fpipbits,bp->hashes[bundlei],bundlei>0?bp->hashes[bundlei-1]:zero,1)) != bundlei || bundlei < 0 || bundlei >= coin->chain->bundlesize )
            {
                printf("B iguana_ramchain_map.(%s) illegal hdrsi.%d bundlei.%d checki.%d\n",fname,hdrsi,bundlei,checki);
                return(0);
            }
            if ( (ptrs[num]= OS_mapfile(fname,&filesizes[num],0)) == 0 )
            {
                printf("error mapping bundlei.%d\n",bundlei);
                return(0);
            }
            //printf("%s mapped ptrs[%d] filesize.%ld bundlei.%d ipbits.%x fpos.%d\n",fname,num,(long)filesizes[num],bundlei,fpipbits,bp->fpos[bundlei]);
            num++;
        }
    }
    return(num);
}

void iguana_bundlemapfree(struct OS_memspace *mem,struct OS_memspace *hashmem,uint32_t *ipbits,void **ptrs,long *filesizes,int32_t num,struct iguana_ramchain *R,int32_t n)
{
    int32_t j;
    for (j=0; j<num; j++)
        if ( ptrs[j] != 0 && filesizes[j] != 0 )
        {
            //printf("unmap.%d/%d: %p %ld\n",j,num,ptrs[j],filesizes[j]);
            munmap(ptrs[j],filesizes[j]);
        }
    myfree(ptrs,n * sizeof(*ptrs));
    myfree(ipbits,n * sizeof(*ipbits));
    myfree(filesizes,n * sizeof(*filesizes));
    if ( R != 0 )
    {
        for (j=0; j<n; j++)
        {
            //printf("R[%d]\n",j);
            R[j].fileptr = 0;
            R[j].filesize = 0;
            iguana_ramchain_free(&R[j],1);
        }
        myfree(R,n * sizeof(*R));
    }
    if ( mem != 0 )
        iguana_mempurge(mem);
    if ( hashmem != 0 )
        iguana_mempurge(hashmem);
}

int32_t iguana_ramchain_expandedsave(struct iguana_info *coin,RAMCHAIN_FUNC,struct iguana_ramchain *newchain,struct OS_memspace *hashmem,int32_t cmpflag,struct iguana_bundle *bp)
{
    static bits256 zero;
    bits256 firsthash2,lasthash2; int32_t err,bundlei,hdrsi,numblocks,firsti,height,retval = -1;
    struct iguana_ramchain checkR,*mapchain; char fname[1024];
    firsthash2 = ramchain->H.data->firsthash2, lasthash2 = ramchain->H.data->lasthash2;
    height = ramchain->height, firsti = ramchain->H.data->firsti, hdrsi = ramchain->H.hdrsi, numblocks = ramchain->numblocks;
    //printf("Apresave T.%d U.%d S.%d P.%d X.%d -> size.%ld firsti.%d\n",ramchain->H.data->numtxids,ramchain->H.data->numunspents,ramchain->H.data->numspends,ramchain->H.data->numpkinds,ramchain->H.data->numexternaltxids,(long)ramchain->H.data->allocsize,firsti);
    iguana_ramchain_setsize(ramchain,ramchain->H.data,bp->n);
    *newchain = *ramchain;
    //memcpy(ramchain->roU2,ramchain->U2,sizeof(*ramchain->U2) * ramchain->H.data->numunspents);
    //memcpy(ramchain->roP2,ramchain->P2,sizeof(*ramchain->P2) * ramchain->H.data->numpkinds);
    memcpy(ramchain->roA,ramchain->A,sizeof(*ramchain->A) * ramchain->H.data->numpkinds);
    memset(ramchain->A,0,sizeof(*ramchain->A) * ramchain->H.data->numpkinds);
    //printf("presave T.%d U.%d S.%d P.%d X.%d -> size.%ld firsti.%d\n",ramchain->H.data->numtxids,ramchain->H.data->numunspents,ramchain->H.data->numspends,ramchain->H.data->numpkinds,ramchain->H.data->numexternaltxids,(long)ramchain->H.data->allocsize,firsti);
    if ( (err= iguana_ramchain_iterate(coin,0,ramchain)) != 0 )
        printf("ERROR.%d iterating presave ramchain hdrsi.%d\n",err,hdrsi);
    else if ( (err= iguana_ramchain_verify(coin,ramchain)) != 0 )
        printf("ERROR.%d verifying presave ramchain hdrsi.%d\n",err,hdrsi);
    else retval = 0;
    printf("postiterateA T.%d U.%d S.%d P.%d X.%d -> size.%ld firsti.%d\n",ramchain->H.data->numtxids,ramchain->H.data->numunspents,ramchain->H.data->numspends,ramchain->H.data->numpkinds,ramchain->H.data->numexternaltxids,(long)ramchain->H.data->allocsize,firsti);
    if ( iguana_ramchain_save(coin,RAMCHAIN_ARG,0,firsthash2,zero,0,bp) < 0 )
        printf("ERROR saving ramchain hdrsi.%d\n",hdrsi);
    else
    {
        //printf("DEST T.%d U.%d S.%d P.%d X.%d -> size.%ld Xoffset.%d\n",ramchain->H.data->numtxids,ramchain->H.data->numunspents,ramchain->H.data->numspends,ramchain->H.data->numpkinds,ramchain->H.data->numexternaltxids,(long)ramchain->H.data->allocsize,(int32_t)ramchain->H.data->Xoffset);
        //printf("free dest hdrs.%d retval.%d\n",bp->hdrsi,retval);
        memset(&checkR,0,sizeof(checkR));
        bundlei = 0;
        if ( cmpflag == 0 )
            iguana_memreset(hashmem);
        if ( (mapchain= iguana_ramchain_map(coin,fname,bp,numblocks,&checkR,cmpflag==0?hashmem:0,0,firsthash2,zero,bundlei,0,1,1)) != 0 )
        {
            iguana_ramchain_link(mapchain,firsthash2,lasthash2,hdrsi,height,0,numblocks,firsti,1);
            iguana_ramchain_extras(mapchain,hashmem);
            //printf("MAP T.%d U.%d S.%d P.%d X.%d -> size.%ld Xoffset.%d\n",mapchain->H.data->numtxids,mapchain->H.data->numunspents,mapchain->H.data->numspends,mapchain->H.data->numpkinds,mapchain->H.data->numexternaltxids,(long)mapchain->H.data->allocsize,(int32_t)mapchain->H.data->Xoffset);
            if ( (err= iguana_ramchain_iterate(coin,0,mapchain)) != 0 )
                printf("err.%d iterate mapped dest\n",err);
            else if ( cmpflag != 0 )
            {
                if ( (err= iguana_ramchain_cmp(mapchain,ramchain,0)) != 0 )
                    printf("err.%d cmp mapchain.%d vs ramchain\n",err,height);
                else
                {
                    printf("BUNDLE.%d iterated and compared\n",height);
                    retval = 0;
                }
            }
            int32_t i; for (i=0; i<IGUANA_NUMLHASHES; i++)
                printf("%08x ",mapchain->H.data->lhashes[i].uints[0]);
            printf("%llx ht.%d\n",(long long)mapchain->H.data->sha256.txid,mapchain->height);
            iguana_ramchain_free(mapchain,cmpflag);
        }
        iguana_mempurge(hashmem);
    }
    return(retval);
}

struct iguana_ramchain *iguana_bundleload(struct iguana_info *coin,struct iguana_bundle *bp)
{
    static bits256 zero;
    struct iguana_blockRO *B; struct iguana_txid *T; int32_t i,firsti = 1; char fname[512];
    struct iguana_block *block; struct iguana_ramchain *mapchain;
    memset(&bp->ramchain,0,sizeof(bp->ramchain));
    if ( (mapchain= iguana_ramchain_map(coin,fname,bp,bp->n,&bp->ramchain,0,0,bp->hashes[0],zero,0,0,0,1)) != 0 )
    {
        iguana_ramchain_link(mapchain,bp->hashes[0],bp->ramchain.lasthash2,bp->hdrsi,bp->bundleheight,0,bp->ramchain.numblocks,firsti,1);
        //char str[65]; printf("bp.%d: T.%d U.%d S.%d P%d X.%d MAPPED %s %p\n",bp->hdrsi,bp->ramchain.H.data->numtxids,bp->ramchain.H.data->numunspents,bp->ramchain.H.data->numspends,bp->ramchain.H.data->numpkinds,bp->ramchain.H.data->numexternaltxids,mbstr(str,bp->ramchain.H.data->allocsize),bp->ramchain.H.data);
        B = (void *)((long)mapchain->H.data + mapchain->H.data->Boffset);
        T = (void *)((long)mapchain->H.data + mapchain->H.data->Toffset);
        for (i=0; i<bp->n; i++)
        {
            if ( (block= bp->blocks[i]) != 0 || (block= iguana_blockhashset(coin,bp->bundleheight+i,bp->hashes[i],1)) != 0 )
            {
                block->queued = 1;
                block->height = bp->bundleheight + i;
                block->hdrsi = bp->hdrsi;
                block->bundlei = i;
                block->fpipbits = (uint32_t)calc_ipbits("127.0.0.1");

                if ( bp->blocks[i] == 0 )
                    bp->blocks[i] = block;
                if ( bits256_nonz(bp->hashes[i]) == 0 )
                    bp->hashes[i] = B[i].hash2;
                _iguana_chainlink(coin,block);
            }
        }
        bp->emitfinish = (uint32_t)time(NULL) + 1;
        /*for (i=1; i<mapchain->H.data->numtxids; i++)
        {break;
            if ( iguana_txidfind(coin,&height,&tx,T[i].txid) == 0 )
                printf("error couldnt find T[%d] %s\n",i,bits256_str(str,T[i].txid));
            else if ( memcmp(&tx,&T[i],sizeof(T[i])) != 0 )
                printf("compare error T[%d] %s\n",i,bits256_str(str,T[i].txid));
        }*/
    }
    if ( mapchain != 0 )
        coin->newramchain++;
    return(mapchain);
}

// helper threads: NUM_HELPERS
int32_t iguana_bundlesaveHT(struct iguana_info *coin,struct OS_memspace *mem,struct OS_memspace *memB,struct iguana_bundle *bp,uint32_t starttime) // helper thread
{
    static int depth; static bits256 zero;
    RAMCHAIN_DESTDECLARE; RAMCHAIN_DECLARE;
    void **ptrs,*ptr; long *filesizes,filesize; uint32_t *ipbits; char fname[1024];
    struct iguana_ramchain *R,*mapchain,*dest,newchain; uint32_t fpipbits,now = (uint32_t)time(NULL);
    int32_t numtxids,numunspents,numspends,numpkinds,numexternaltxids,fpos; struct iguana_block *block;
    struct OS_memspace HASHMEM; int32_t err,j,num,hdrsi,bundlei,firsti= 1,retval = -1;
    B = 0, Ux = 0, Sx = 0, P = 0, A = 0, X = 0, TXbits = 0, PKbits = 0, U = 0, S = 0, T = 0;//U2 = 0, P2 = 0,
    R = mycalloc('s',bp->n,sizeof(*R));
    ptrs = mycalloc('w',bp->n,sizeof(*ptrs));
    ipbits = mycalloc('w',bp->n,sizeof(*ipbits));
    filesizes = mycalloc('f',bp->n,sizeof(*filesizes));
    if ( (num= iguana_bundlefiles(coin,ipbits,ptrs,filesizes,bp)) == 0 )
    {
        iguana_bundlemapfree(0,0,ipbits,ptrs,filesizes,bp->n,R,bp->n);
        return(-1);
    }
    for (bundlei=numtxids=numunspents=numspends=0; bundlei<bp->n; bundlei++)
    {
        if ( (block= bp->blocks[bundlei]) != 0 )
            fpipbits = block->fpipbits, fpos = block->fpos;
        else fpipbits = fpos = 0;
        mapchain = &R[bundlei];
        for (j=0; j<num; j++)
            if ( ipbits[j] == fpipbits )
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
        mapchain->H.data = (void *)((long)ptr + fpos);
        mapchain->H.ROflag = 1;
        if ( fpos+mapchain->H.data->allocsize > filesize || iguana_ramchain_size(MAPCHAIN_ARG,1) != mapchain->H.data->allocsize )
        {
            printf("iguana_bundlesaveHT ipbits.%x size mismatch %ld vs %ld vs filesize.%ld fpos.%ld bundlei.%d expanded.%d\n",fpipbits,(long)iguana_ramchain_size(MAPCHAIN_ARG,1),(long)mapchain->H.data->allocsize,(long)filesize,(long)fpos,bundlei,mapchain->expanded);
            //getchar();
            break;
        }
        else if ( memcmp(bp->hashes[bundlei].bytes,mapchain->H.data->firsthash2.bytes,sizeof(bits256)) != 0 )
        {
            char str[65],str2[65]; printf("iguana_bundlesaveHT hash2 mismatch %s vs %s\n",bits256_str(str,bp->hashes[bundlei]),bits256_str(str2,mapchain->H.data->firsthash2));
            break;
        }
        iguana_ramchain_link(mapchain,bp->hashes[bundlei],bp->hashes[bundlei],bp->hdrsi,bp->bundleheight+bundlei,bundlei,1,firsti,1);
        numtxids += (mapchain->H.data->numtxids - 1);
        numunspents += (mapchain->H.data->numunspents - 1);
        numspends += (mapchain->H.data->numspends - 1);
        //printf("(%d %d %d) ",numtxids,numunspents,numspends);
        //printf("%d ",numtxids);
    }
    if ( bundlei != bp->n )
    {
        iguana_bundlemapfree(0,0,ipbits,ptrs,filesizes,num,R,bp->n);
        printf("error mapping hdrsi.%d bundlei.%d\n",bp->hdrsi,bundlei);
        return(-1);
    }
    //printf("-> total (%d %d %d)\n",numtxids,numunspents,numspends);
    numpkinds = numunspents;
    numexternaltxids = numspends;
    dest = &bp->ramchain;
    //printf("E.%d depth.%d start bundle ramchain %d at %u started.%u lag.%d\n",coin->numemitted,depth,bp->bundleheight,now,starttime,now-starttime);
    depth++;
    if ( iguana_ramchain_alloc(coin,dest,mem,&HASHMEM,numtxids,numunspents,numspends,numpkinds,numexternaltxids,bp->bundleheight,bp->n) < 0 )
    {
        iguana_bundlemapfree(mem,&HASHMEM,ipbits,ptrs,filesizes,num,R,bp->n);
        return(-1);
    }
    iguana_ramchain_link(dest,bp->hashes[0],bp->hashes[bp->n-1],bp->hdrsi,bp->bundleheight,0,bp->n,firsti,0);
    _iguana_ramchain_setptrs(RAMCHAIN_DESTPTRS,dest->H.data);
    iguana_ramchain_extras(dest,&HASHMEM);
    dest->H.txidind = dest->H.unspentind = dest->H.spendind = dest->pkind = dest->H.data->firsti;
    dest->externalind = 0;
    //printf("\n");
    for (bundlei=0; bundlei<bp->n; bundlei++)
    {
        if ( (block= bp->blocks[bundlei]) != 0 )
        {
            iguana_blocksetcounters(coin,block,dest);
            coin->blocks.RO[bp->bundleheight+bundlei] = block->RO;
        }
        //printf("(%d %d) ",R[bundlei].H.data->numtxids,dest->H.txidind);
        if ( (err= iguana_ramchain_iterate(coin,dest,&R[bundlei])) != 0 )
        {
            printf("error ramchain_iterate hdrs.%d bundlei.%d\n",bp->hdrsi,bundlei);
            break;
        }
    }
    depth--;
    if ( bundlei == bp->n && iguana_ramchain_expandedsave(coin,RAMCHAIN_DESTARG,&newchain,&HASHMEM,0,bp) == 0 )
    {
        char str[65],str2[65]; printf("%s d.%d ht.%d %s saved lag.%d elapsed.%ld\n",bits256_str(str2,newchain.H.data->sha256),depth,dest->height,mbstr(str,dest->H.data->allocsize),now-starttime,time(NULL)-now);
        retval = 0;
    }
    iguana_bundlemapfree(mem,&HASHMEM,ipbits,ptrs,filesizes,num,R,bp->n);
    if ( retval == 0 )
    {
        //printf("delete %d files hdrs.%d retval.%d\n",num,bp->hdrsi,retval);
        for (j=0; j<num; j++)
        {
            if ( iguana_peerfname(coin,&hdrsi,"tmp",fname,ipbits[j],bp->hashes[0],zero,1) >= 0 )
                coin->peers.numfiles -= OS_removefile(fname,0);
            else printf("error removing.(%s)\n",fname);
        }
    }
    iguana_ramchain_free(dest,0);
    bp->ramchain = newchain;
    if ( 0 )
    {
        bp->ramchain.hashmem = 0;
        bp->ramchain.txids = 0;
        bp->ramchain.pkhashes = 0;
        bp->ramchain.fileptr = 0;
        bp->ramchain.filesize = 0;
    }
    else iguana_bundleload(coin,bp);
    return(retval);
}

void iguana_mergefree(struct OS_memspace *mem,struct iguana_ramchain *A,struct iguana_ramchain *B,struct OS_memspace *hashmem,struct OS_memspace *hashmemA,struct OS_memspace *hashmemB)
{
    if ( A != 0 )
        iguana_ramchain_free(A,0);
    if ( B != 0 )
        iguana_ramchain_free(B,0);
    if ( mem != 0 )
        iguana_mempurge(mem);
    if ( hashmemA != 0 )
        iguana_mempurge(hashmemA);
    if ( hashmemB != 0 )
        iguana_mempurge(hashmemB);
}

int32_t iguana_bundlemergeHT(struct iguana_info *coin,struct OS_memspace *mem,struct OS_memspace *memB,struct iguana_bundle *bp,struct iguana_bundle *nextbp,uint32_t starttime)
{
    static int32_t depth; static bits256 zero;
    RAMCHAIN_DESTDECLARE; struct OS_memspace HASHMEM,HASHMEMA,HASHMEMB;
    uint32_t now = (uint32_t)time(NULL); char str[65],fnameA[1024],fnameB[1024];
    struct iguana_ramchain _Achain,_Bchain,*A,*B,R,newchain,*dest = &R; int32_t err,retval = -1,firsti = 1;
    memset(mem,0,sizeof(*mem));
    memset(&HASHMEMA,0,sizeof(HASHMEMA));
    iguana_meminit(&HASHMEMA,"hashmemA",0,iguana_hashmemsize(bp->ramchain.H.txidind,bp->ramchain.H.unspentind,bp->ramchain.H.spendind,bp->ramchain.pkind,bp->ramchain.externalind) + 4096,0);
    memset(&HASHMEMB,0,sizeof(HASHMEMB));
    iguana_meminit(&HASHMEMB,"hashmemB",0,iguana_hashmemsize(nextbp->ramchain.H.txidind,nextbp->ramchain.H.unspentind,nextbp->ramchain.H.spendind,nextbp->ramchain.pkind,nextbp->ramchain.externalind) + 4096,0);
    memset(&_Achain,0,sizeof(_Achain)); A = &_Achain;
    memset(&_Bchain,0,sizeof(_Bchain)); B = &_Bchain;
    if ( (A= iguana_ramchain_map(coin,fnameA,bp,bp->ramchain.numblocks,A,&HASHMEMA,0,bp->hashes[0],zero,0,0,1,1)) != 0 )
    {
        iguana_ramchain_link(A,bp->hashes[0],bp->ramchain.lasthash2,bp->hdrsi,bp->bundleheight,0,bp->ramchain.numblocks,firsti,1);
    }
    if ( (B= iguana_ramchain_map(coin,fnameB,bp,nextbp->ramchain.numblocks,B,&HASHMEMB,0,nextbp->hashes[0],zero,0,0,1,1)) != 0 )
    {
        iguana_ramchain_link(B,bp->hashes[0],nextbp->ramchain.lasthash2,nextbp->hdrsi,nextbp->bundleheight,0,nextbp->ramchain.numblocks,firsti,1);
    }
    if ( A == 0 || B == 0 || A->H.data == 0 || B->H.data == 0 || (A->H.data->allocsize + B->H.data->allocsize) > IGUANA_MAXRAMCHAINSIZE )
    {
        printf("MERGE error %d[%d] %d[%d]\n",A->height,A->numblocks,B->height,B->numblocks);
        iguana_mergefree(mem,A,B,&HASHMEM,&HASHMEMA,&HASHMEMB);
        return(-1);
    }
    if ( A->H.data != 0 && B->H.data != 0 && B->height == A->height+A->numblocks )
    {
        if ( iguana_ramchain_alloc(coin,dest,mem,&HASHMEM,(A->H.data->numtxids+B->H.data->numtxids),(A->H.data->numunspents+B->H.data->numunspents),(A->H.data->numspends+B->H.data->numspends),(A->H.data->numpkinds+B->H.data->numpkinds),(A->H.data->numexternaltxids+B->H.data->numexternaltxids),A->height,A->numblocks + B->numblocks) < 0 )
        {
            printf("depth.%d ht.%d fsize.%s ERROR alloc lag.%d elapsed.%ld\n",depth,dest->height,mbstr(str,dest->H.data->allocsize),now-starttime,time(NULL)-now);
            iguana_mergefree(mem,A,B,&HASHMEM,&HASHMEMA,&HASHMEMB);
            return(-1);
        }
        depth++;
        iguana_ramchain_link(dest,A->H.data->firsthash2,B->H.data->lasthash2,A->H.hdrsi,A->height,0,A->numblocks+B->numblocks,firsti,0);
        _iguana_ramchain_setptrs(RAMCHAIN_DESTPTRS,dest->H.data);
        iguana_ramchain_extras(dest,&HASHMEM);
        dest->H.txidind = dest->H.unspentind = dest->H.spendind = dest->pkind = dest->H.data->firsti;
        dest->externalind = 0;
        if ( (err= iguana_ramchain_iterate(coin,dest,A)) != 0 )
            printf("error.%d ramchain_iterate A.%d\n",err,A->height);
        else if ( (err= iguana_ramchain_iterate(coin,dest,B)) != 0 )
            printf("error.%d ramchain_iterate B.%d\n",err,B->height);
        else if ( iguana_ramchain_expandedsave(coin,RAMCHAIN_DESTARG,&newchain,&HASHMEM,0,0) == 0 )
        {
            printf("merging isnt setup to save the blockROs\n");
            printf("depth.%d ht.%d fsize.%s MERGED %d[%d] and %d[%d] lag.%d elapsed.%ld bp.%d -> %d\n",depth,dest->height,mbstr(str,dest->H.data->allocsize),A->height,A->numblocks,B->height,B->numblocks,now-starttime,time(NULL)-now,bp->bundleheight,nextbp->bundleheight);
            iguana_mergefree(mem,A,B,&HASHMEM,&HASHMEMA,&HASHMEMB);
            bp->mergefinish = 0;
            nextbp->mergefinish = (uint32_t)time(NULL);
            bp->nextbp = nextbp->nextbp;
            newchain.hashmem = 0;
            retval = 0;
            nextbp->ramchain = bp->ramchain = newchain;
            OS_removefile(fnameA,0);
            OS_removefile(fnameB,0);
        }
        else
        {
            bp->mergefinish = nextbp->mergefinish = 0;
            iguana_mergefree(mem,A,B,&HASHMEM,&HASHMEMA,&HASHMEMB);
        }
        iguana_ramchain_free(dest,0);
        depth--;
    } else printf("error merging A.%d [%d] and B.%d [%d]\n",A->height,A->numblocks,B->height,B->numblocks);
    coin->merging--;
    return(retval);
}

void iguana_ramchainmerge(struct iguana_info *coin) // jl777: verify prev/next hash2
{
    struct iguana_bundle *bp,*nextbp,*A,*B; int64_t total = 0; int32_t n,flag = 0;
    if ( coin->bundlescount <= 0 || coin->merging > 0 )
        return;
    A = B = 0;
    n = 0;
    bp = coin->bundles[0];
    while ( bp != 0 && (nextbp= bp->nextbp) != 0 )
    {
        n++;
        if ( nextbp != 0 && bp != 0 && bp->emitfinish > coin->startutc && nextbp->emitfinish > coin->startutc && bp->mergefinish == 0 && nextbp->mergefinish == 0 && bp->ramchain.datasize + nextbp->ramchain.datasize < IGUANA_MAXRAMCHAINSIZE )
        {
            if ( total == 0 || (bp->ramchain.datasize + nextbp->ramchain.datasize) < total )
            {
                total = (bp->ramchain.datasize + nextbp->ramchain.datasize);
                A = bp, B = nextbp;
            }
        }
        bp = nextbp;
    }
    if ( A != 0 && B != 0 )
    {
        bp = A, nextbp = B;
        bp->mergefinish = nextbp->mergefinish = 1;
        flag++;
        char str[65]; printf("start merge %d[%d] + %d[%d] %s\n",bp->bundleheight,bp->ramchain.numblocks,nextbp->bundleheight,nextbp->ramchain.numblocks,mbstr(str,bp->ramchain.datasize + nextbp->ramchain.datasize));
        coin->merging++;
        iguana_mergeQ(coin,bp,nextbp);
    }
    if ( flag != 0 )
    {
        bp = coin->bundles[0];
        while ( bp != 0 && (nextbp= bp->nextbp) != 0 )
        {
            printf("%d[%d].%d ",bp->bundleheight,bp->ramchain.numblocks,bp->mergefinish);
            bp = nextbp;
        }
        printf("bundles.%d\n",n);
    }
}

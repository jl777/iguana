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

#define uthash_malloc(size) iguana_memalloc(mem,size,1)
#define uthash_free iguana_stub
#define HASH_BLOOM 16
#define HASH_INITIAL_NUM_BUCKETS_LOG2 8

#include "iguana777.h"
void iguana_stub(void *ptr,int size) { }//printf("uthash_free ptr.%p %d\n",ptr,size); }

#define iguana_hashfind(coin,selector,key) iguana_hashsetPT(coin,selector,key,-1)

struct iguana_kvitem *iguana_hashsetPT(struct iguana_peer *addr,int32_t selector,void *key,int32_t itemind)
{
    struct iguana_kvitem *ptr = 0; int32_t allocsize,keylen; struct iguana_memspace *mem;
    allocsize = (int32_t)(sizeof(*ptr));
    if ( selector == 'T' )
    {
        keylen = sizeof(bits256);
        HASH_FIND(hh,addr->txids,key,keylen,ptr);
    }
    else if ( selector == 'P' )
    {
        keylen = 20;
        HASH_FIND(hh,addr->pkhashes,key,keylen,ptr);
    }
    else return(0);
    mem = &addr->HASHMEM;
    if ( ptr == 0 && itemind >= 0 )
    {
        if ( addr->HASHMEM.totalsize != 0 )
            ptr = iguana_memalloc(mem,allocsize,1);
        else ptr = mycalloc('p',1,allocsize);//, ptr->allocsize = allocsize;
        if ( ptr == 0 )
            printf("fatal alloc error in hashset\n"), exit(-1);
        //printf("%s ptr.%p allocsize.%d key.%p keylen.%d itemind.%d\n",addr->ipaddr,ptr,allocsize,key,keylen,itemind);
        ptr->hh.itemind = itemind;
        if ( selector == 'T' )
            HASH_ADD_KEYPTR(hh,addr->txids,key,keylen,ptr);
        else HASH_ADD_KEYPTR(hh,addr->pkhashes,key,keylen,ptr);
    }
    if ( ptr != 0 )
    {
        struct iguana_kvitem *tmp;
        HASH_FIND(hh,((selector == 'T') ? addr->txids : addr->pkhashes),key,keylen,tmp);
        char str[65];
        init_hexbytes_noT(str,key,keylen);
        if ( tmp != ptr )
            printf("%s search error %p != %p\n",str,ptr,tmp), getchar();
        // else printf("added.(%s) height.%d %p\n",str,itemind,ptr);
    }
    return(ptr);
}

struct iguana_txblock *iguana_peertxdata(struct iguana_info *coin,int32_t *bundleip,char *fname,struct iguana_memspace *mem,uint32_t ipbits,bits256 hash2)
{
    int32_t bundlei,datalen,checki,hdrsi,fpos; char str[65],str2[65]; FILE *fp;
    bits256 checkhash2; struct iguana_txblock *txdata = 0;
    if ( (bundlei= iguana_peerfname(coin,&hdrsi,fname,ipbits,hash2)) >= 0 )
    {
        if ( (fp= fopen(fname,"rb")) != 0 )
        {
            fseek(fp,bundlei * sizeof(bundlei),SEEK_SET);
            fread(&fpos,1,sizeof(fpos),fp);
            fseek(fp,fpos,SEEK_SET);
            fread(&checki,1,sizeof(checki),fp);
            if ( ftell(fp)-sizeof(checki) == fpos && bundlei == checki )
            {
                fread(&checkhash2,1,sizeof(checkhash2),fp);
                if ( memcmp(hash2.bytes,checkhash2.bytes,sizeof(hash2)) == 0 )
                {
                    fread(&datalen,1,sizeof(datalen),fp);
                    if ( datalen < (mem->totalsize - mem->used - 4) )
                    {
                        if ( (txdata= iguana_memalloc(mem,datalen,0)) != 0 )
                        {
                            fread(txdata,1,datalen,fp);
                            if ( txdata->datalen != datalen || txdata->block.bundlei != bundlei )
                            {
                                printf("%s peertxdata txdata->datalen.%d != %d bundlei.%d vs %d\n",bits256_str(str,txdata->block.hash2),txdata->datalen,datalen,txdata->block.bundlei,bundlei);
                                getchar();
                                txdata = 0;
                                iguana_memreset(mem);
                            } //else printf("SUCCESS txdata.%s bundlei.%d fpos.%d T.%d U.%d S.%d P.%d\n",bits256_str(str,txdata->block.hash2),bundlei,fpos,txdata->numtxids,txdata->numunspents,txdata->numspends,txdata->numpkinds);
                        } else printf("peertxdata error allocating txdata\n");
                    } else printf("mismatch peertxdata datalen %d vs %ld totalsize %ld\n",datalen,mem->totalsize - mem->used - 4,(long)mem->totalsize);
                } else printf("peertxdata hash mismatch %s != %s\n",bits256_str(str,hash2),bits256_str(str2,checkhash2));
            } else printf("peertxdata bundlei.%d != checki.%d, fpos.%d ftell.%ld\n",bundlei,checki,fpos,ftell(fp));
            fclose(fp);
        } else printf("cant find file.(%s)\n",fname);
    } //else printf("bundlei.%d\n",bundlei);
    *bundleip = bundlei;
    return(txdata);
}

int32_t iguana_peerfname(struct iguana_info *coin,int32_t *hdrsip,char *fname,uint32_t ipbits,bits256 hash2)
{
    struct iguana_bundle *bp = 0; int32_t bundlei; char str[65];
    *hdrsip = -1;
    if ( ipbits == 0 )
        printf("illegal ipbits.%d\n",ipbits), getchar();
    if ( (bp= iguana_bundlefind(coin,&bp,&bundlei,hash2)) != 0 )
        hash2 = bp->hashes[0], *hdrsip = bp->ramchain.hdrsi;
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

struct iguana_txblock *iguana_peertxsave(struct iguana_info *coin,int32_t *hdrsip,int32_t *bundleip,char *fname,struct iguana_peer *addr,struct iguana_txblock *txdata)
{
    int32_t fpos,bundlei,i,z; FILE *fp;
    fpos = 0;
    *bundleip = bundlei = iguana_peerfname(coin,hdrsip,fname,addr->ipbits,txdata->block.hash2);
    if ( bundlei < 0 || bundlei >= coin->chain->bundlesize )
    {
        printf(" wont save.(%s) bundlei.%d\n",fname,bundlei);
        return(0);
    }
    txdata->block.hdrsi = *hdrsip;
    txdata->block.bundlei = bundlei;
    if ( (fp= fopen(fname,"rb+")) == 0 )
    {
        if ( (fp= fopen(fname,"wb")) != 0 )
        {
            z = -1;
            coin->peers.numfiles++;
            for (i=0; i<coin->chain->bundlesize; i++)
                fwrite(&z,1,sizeof(z),fp);
            fclose(fp);
            fp = fopen(fname,"rb+");
        }
    }
    if ( fp != 0 )
    {
        fseek(fp,0,SEEK_END);
        fpos = (int32_t)ftell(fp);
        //printf("%s fpos.%d: bundlei.%d datalen.%d\n",fname,fpos,bundlei,txdata->datalen);
        fwrite(&bundlei,1,sizeof(bundlei),fp);
        fwrite(&txdata->block.hash2,1,sizeof(txdata->block.hash2),fp);
        fwrite(&txdata->datalen,1,sizeof(txdata->datalen),fp);
        fwrite(txdata,1,txdata->datalen,fp);
        fseek(fp,bundlei * sizeof(bundlei),SEEK_SET);
        //printf("bundlei[%d] <- fpos.%d\n",bundlei,fpos);
        fwrite(&fpos,1,sizeof(fpos),fp);
        fclose(fp);
        //for (i=0; i<txdata->numpkinds; i++)
        //    printf("%016lx ",*(long *)((struct iguana_pkhash *)((long)txdata + txdata->pkoffset))[i].rmd160);
        //printf("create.(%s) %d ",fname,bundlei,coin->peers.numfiles);
        //printf("bundlei.%d datalen.%d T.%d U.%d S.%d P.%d X.%d\n",bundlei,txdata->datalen,txdata->numtxids,txdata->numunspents,txdata->numspends,txdata->numpkinds,txdata->numexternaltxids);
        return(txdata);
    }
    return(0);
}

struct iguana_txblock *iguana_blockramchainPT(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_txblock *origtxdata,struct iguana_msgtx *txarray,int32_t txn_count,uint8_t *data,int32_t recvlen)
{
    struct iguana_txid *T,*t; struct iguana_unspent *U,*u; struct iguana_spend *S,*s;
    bits256 *externalT; struct iguana_kvitem *ptr; struct iguana_pkhash *P;
    struct iguana_memspace *txmem,*hashmem; struct iguana_msgtx *tx; struct iguana_txblock *txdata = 0;
    int32_t i,j,hdrsi,numvins,numvouts,numexternal,numpkinds,scriptlen,sequence,bundlei = -2;
    uint32_t txidind,unspentind,spendind,pkind; uint8_t *script,rmd160[20]; char fname[512];
    struct iguana_bundle *bp = 0;
    if ( iguana_bundlefind(coin,&bp,&bundlei,origtxdata->block.hash2) == 0 )
        return(0);
    SETBIT(bp->recv,bundlei);
    bp->recvlens[bundlei] = recvlen;
    txmem = &addr->TXDATA, hashmem = &addr->HASHMEM;
    iguana_memreset(txmem), iguana_memreset(hashmem);
    addr->txids = addr->pkhashes = 0;
    //printf("iguana_blockramchainPT recvlen.%d txn_count.%d height.%d + %d\n",recvlen,txn_count,bp->ramchain.bundleheight,bundlei);
    if ( (txdata= iguana_ramchainptrs(&T,&U,&S,&P,0,txmem,origtxdata)) == 0 || T == 0 || U == 0 || S == 0 || P == 0 )
    {
        printf("fatal error getting txdataptrs\n");
        exit(-1);
        return(0);
    }
    txidind = unspentind = spendind = pkind = 0;
    for (i=numvouts=numpkinds=0; i<txn_count; i++,txidind++)
    {
        tx = &txarray[i];
        t = &T[txidind];
        t->txid = tx->txid, t->txidind = txidind, t->firstvout = unspentind, t->numvouts = tx->tx_out;
        iguana_hashsetPT(addr,'T',t->txid.bytes,txidind);
        for (j=0; j<tx->tx_out; j++,numvouts++,unspentind++)
        {
            u = &U[unspentind];
            script = tx->vouts[j].pk_script, scriptlen = tx->vouts[j].pk_scriptlen;
            iguana_calcrmd160(coin,rmd160,script,scriptlen,tx->txid);
            //char str[65]; init_hexbytes_noT(str,rmd160,20), printf("pkhashes.%p %s %s new pkind.%d pkoffset.%d %d\n",addr->pkhashes,addr->ipaddr,str,numpkinds,txdata->pkoffset,(int32_t)((long)&P[numpkinds] - (long)txdata));
            if ( (ptr= iguana_hashfind(addr,'P',rmd160)) == 0 )
            {
                memcpy(P[numpkinds].rmd160,rmd160,sizeof(rmd160));
                if ( (ptr= iguana_hashsetPT(addr,'P',&P[numpkinds],numpkinds)) == 0 )
                    printf("fatal error adding pkhash\n"), getchar();
                //printf("added ptr.%p\n",ptr);
                numpkinds++;
            } //else printf("found %p[%d] for (%s)\n",ptr,ptr->hh.itemind,str);
            u->value = tx->vouts[j].value, u->txidind = txidind;
            u->pkind = ptr->hh.itemind;
            P[u->pkind].firstunspentind = unspentind;
            // prevunspentind requires having accts, so that waits for third pass
        }
    }
    //printf("reallocP.%p -> ",P);
    if ( (txdata->numpkinds= numpkinds) > 0 )
        P = iguana_memalloc(txmem,sizeof(*P) * numpkinds,0);
    //printf("%p\n",P);
    externalT = iguana_memalloc(txmem,0,1);
    txidind = 0;
    for (i=numvins=numexternal=0; i<txn_count; i++,txidind++)
    {
        tx = &txarray[i];
        t = &T[txidind];
        t->firstvin = spendind;
        for (j=0; j<tx->tx_in; j++)
        {
            script = tx->vins[j].script, scriptlen = tx->vins[j].scriptlen;
            s = &S[spendind];
            if ( (sequence= tx->vins[j].sequence) != (uint32_t)-1 )
                s->diffsequence = 1;
            s->vout = tx->vins[j].prev_vout;
            if ( s->vout != 0xffff )
            {
                if ( (ptr= iguana_hashfind(addr,'T',tx->vins[j].prev_hash.bytes)) != 0 )
                {
                    if ( (s->spendtxidind= ptr->hh.itemind) >= txdata->numtxids )
                    {
                        s->external = 1;
                        s->spendtxidind -= txdata->numtxids;
                    }
                }
                else
                {
                    s->external = 1;
                    externalT[numexternal] = tx->vins[j].prev_hash;
                    iguana_hashsetPT(addr,'T',externalT[numexternal].bytes,txdata->numtxids + numexternal);
                    s->spendtxidind = numexternal++;
                }
                spendind++;
                numvins++;
                //printf("spendind.%d\n",spendind);
            } //else printf("vout.%x\n",s->vout);
            // prevspendind requires having accts, so that waits for third pass
        }
        t->numvins = numvins;
    }
    if ( (txdata->numexternaltxids= numexternal) > 0 )
        externalT = iguana_memalloc(txmem,sizeof(*externalT) * numexternal,0);
    txdata->datalen = (int32_t)txmem->used;
    txdata->numspends = numvins;
    txdata->numpkinds = numpkinds;
    txdata->numpkinds = txn_count;
    txdata->block.ipbits = addr->ipbits;
    //char str[65],buf[9999];
    //for (j=buf[0]=0; j<numpkinds; j++)
    //    init_hexbytes_noT(str,P[j].rmd160,20), sprintf(buf+strlen(buf),"(%d %s) ",j,str);
    //printf("%s bundlei.%d T.%d U.%d S.%d P.%d recvlen.%d -> %d\n",buf,bundlei,txdata->numtxids,txdata->numunspents,txdata->numspends,txdata->numpkinds,recvlen,txdata->datalen);
    if ( numvouts != txdata->numunspents || i != txdata->numtxids )
    {
        printf("counts mismatch: numvins %d != %d txdata->numvins || numvouts %d != %d txdata->numvouts || i %d != %d txdata->numtxids\n",numvins,txdata->numspends,numvouts,txdata->numunspents,i,txdata->numtxids);
        getchar();
        exit(-1);
    }
    else
    {
        static int32_t maxrecvlen,maxdatalen,maxhashmem; static double recvsum,datasum;
        recvsum += recvlen, datasum += txdata->datalen;
        if ( recvlen > maxrecvlen )
            printf("[%.3f] %.0f/%.0f maxrecvlen %d -> %d\n",recvsum/datasum,recvsum,datasum,maxrecvlen,recvlen), maxrecvlen = recvlen;
        if ( txdata->datalen > maxdatalen )
            printf("[%.3f] %.0f/%.0f maxdatalen %d -> %d\n",recvsum/datasum,recvsum,datasum,maxdatalen,txdata->datalen), maxdatalen = txdata->datalen;
        if ( hashmem != 0 && hashmem->used > maxhashmem )
            printf("[%.3f] %.0f/%.0f maxhashmem %d -> %ld\n",recvsum/datasum,recvsum,datasum,maxhashmem,hashmem->used), maxhashmem = (int32_t)hashmem->used;
        if ( (rand() % 10000) == 0 )
            printf("[%.3f] %.0f/%.0f recvlen vs datalen\n",recvsum/datasum,recvsum,datasum);
        if ( origtxdata != 0 )
        {
            origtxdata->numspends = txdata->numspends;
            origtxdata->numpkinds = txdata->numpkinds;
            origtxdata->numexternaltxids = txdata->numexternaltxids;
        }
    }
    if ( iguana_peertxsave(coin,&hdrsi,&bundlei,fname,addr,txdata) == txdata )
    {
        int32_t checki; struct iguana_txblock *checktx; struct iguana_ramchain R,*ptr = &R;
        if ( 1 && (checktx= iguana_peertxdata(coin,&checki,fname,txmem,addr->ipbits,txdata->block.hash2)) != 0 && checki == bundlei )
        {
            if ( iguana_ramchainset(coin,ptr,checktx) == ptr )
            {
                char str[65]; int32_t j,err;
                ptr->txids = addr->txids;
                ptr->pkhashes = addr->pkhashes;
                if ( (err= iguana_ramchainverifyPT(coin,ptr)) != 0 )
                {
                    for (j=0; j<ptr->numpkinds; j++)
                        init_hexbytes_noT(str,ptr->P[j].rmd160,20), printf("[%d %s] ",j,str);
                    printf("check err.%d ramchain.%s bundlei.%d T.%d U.%d S.%d P.%d\n",err,bits256_str(str,ptr->hash2),bundlei,ptr->numtxids,ptr->numunspents,ptr->numspends,ptr->numpkinds);
                }
            }
        }
    }
    //printf("free addrtables %p %p\n",addr->txids,addr->pkhashes);
    //iguana_hashfree(addr->txids,0);
    //iguana_hashfree(addr->pkhashes,0);
   // printf("numpkinds.%d numspends.%d\n",txdata->numpkinds,txdata->numspends);
    return(txdata);
}

// two passes to check data size
int32_t iguana_rwvin(int32_t rwflag,struct iguana_memspace *mem,uint8_t *serialized,struct iguana_msgvin *msg)
{
    int32_t len = 0;
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(msg->prev_hash),msg->prev_hash.bytes);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->prev_vout),&msg->prev_vout);
    //printf("vin.(%s) %d\n",bits256_str(msg->prev_hash),msg->prev_vout);
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
    ptr->bp = bp, ptr->hdrsi = bp->ramchain.hdrsi;
    ptr->type = 'E';
    printf("%s EMIT.%d[%d] emitfinish.%u\n",coin->symbol,ptr->hdrsi,bp->n,bp->emitfinish);
    queue_enqueue("helperQ",&helperQ,&ptr->DL,0);
}

void iguana_flushQ(struct iguana_info *coin,struct iguana_peer *addr)
{
    struct iguana_helper *ptr;
    if ( time(NULL) > addr->lastflush+3 )
    {
        ptr = mycalloc('i',1,sizeof(*ptr));
        ptr->allocsize = sizeof(*ptr);
        ptr->coin = coin;
        ptr->addr = addr;
        ptr->type = 'F';
        //printf("FLUSH.%s %u lag.%d\n",addr->ipaddr,addr->lastflush,(int32_t)(time(NULL)-addr->lastflush));
        addr->lastflush = (uint32_t)time(NULL);
        queue_enqueue("helperQ",&helperQ,&ptr->DL,0);
    }
}

// helper threads: NUM_HELPERS

int32_t iguana_bundlesaveHT(struct iguana_info *coin,struct iguana_memspace *mem,struct iguana_memspace *memB,struct iguana_bundle *bp) // helper thread
{
    struct iguana_txblock *ptr; struct iguana_ramchain *ptrs[IGUANA_MAXBUNDLESIZE],*ramchains;
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
                    printf("peertxdata.%d bundlei.%d, i.%d block->bundlei.%d\n",bp->ramchain.hdrsi,bundlei,i,ptr->block.bundlei);
                ptrs[i] = &ramchains[i];
                //char str[65];
                //printf("received txdata.%s bundlei.%d T.%d U.%d S.%d P.%d\n",bits256_str(str,ptr->block.hash2),bundlei,ptr->numtxids,ptr->numunspents,ptr->numspends,ptr->numpkinds);
                if ( iguana_ramchainset(coin,ptrs[i],ptr) == ptrs[i] )
                {
                    char str[65]; int32_t j,err;
                    for (j=0; j<ptrs[i]->numpkinds; j++)
                        init_hexbytes_noT(str,ptrs[i]->P[j].rmd160,20), printf("%s ",str);
                    err = iguana_ramchainverifyPT(coin,ptrs[i]);
                    printf("conv err.%d ramchain.%s bundlei.%d T.%d U.%d S.%d P.%d\n",err,bits256_str(str,ptrs[i]->hash2),bundlei,ptrs[i]->numtxids,ptrs[i]->numunspents,ptrs[i]->numspends,ptrs[i]->numpkinds);
                    ptrs[i]->firsti = 0;
                    if ( block->recvlen > maxrecv )
                        maxrecv = block->recvlen;
                    estimatedsize += block->recvlen;
                    flag++;
                } else printf("error setting ramchain.%d\n",i);
            }
            else
            {
                printf("error (%s) hdrs.%d ptr[%d]\n",fname,bp->ramchain.hdrsi,i);
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
    return(flag);
}

int32_t iguana_helpertask(FILE *fp,struct iguana_memspace *mem,struct iguana_memspace *memB,struct iguana_helper *ptr)
{
    struct iguana_info *coin; struct iguana_peer *addr; struct iguana_bundle *bp;
    coin = ptr->coin, addr = ptr->addr;
    if ( ptr->type == 'F' )
    {
        if ( addr != 0 && addr->fp != 0 )
        {
            //printf("flush.%s %p\n",addr->ipaddr,addr->fp);
            fflush(addr->fp);
        }
    }
    else if ( ptr->type == 'E' )
    {
        //printf("emitQ coin.%p bp.%p\n",ptr->coin,ptr->bp);
        if ( (coin= ptr->coin) != 0 )
        {
            if ( (bp= ptr->bp) != 0 )
            {
                bp->emitfinish = (uint32_t)time(NULL);
#ifdef __APPLE__
                if ( iguana_bundlesaveHT(coin,mem,memB,bp) == 0 )
#endif
                    coin->numemitted++;
            }
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

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

queue_t helperQ;
uint64_t Tx_allocated,Tx_allocsize,Tx_freed,Tx_freesize;

int64_t iguana_MEMallocated(struct iguana_info *coin)
{
    int64_t total = coin->TMPallocated;
    if ( Tx_allocsize > Tx_freesize )
        total += (Tx_allocsize - Tx_freesize);
    //total += coin->R.RSPACE.openfiles * coin->R.RSPACE.size;
    //total += iguana_packetsallocated(coin);
    return(total);
}
// two passes to check data size
int32_t iguana_rwvin(int32_t rwflag,uint8_t *serialized,struct iguana_msgvin *msg)
{
    int32_t len = 0;
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(msg->prev_hash),msg->prev_hash.bytes);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->prev_vout),&msg->prev_vout);
    //printf("vin.(%s) %d\n",bits256_str(msg->prev_hash),msg->prev_vout);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->scriptlen);
    if ( rwflag == 0 )
        msg->script = mycalloc('s',1,msg->scriptlen);
    len += iguana_rwmem(rwflag,&serialized[len],msg->scriptlen,msg->script);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->sequence),&msg->sequence);
    //int i; for (i=0; i<msg->scriptlen; i++)
    // printf("%02x ",msg->script[i]);
    //printf(" inscriptlen.%d, prevhash.%llx prev_vout.%d | ",msg->scriptlen,(long long)msg->prev_hash.txid,msg->prev_vout);
    return(len);
}

int32_t iguana_rwvout(int32_t rwflag,uint8_t *serialized,struct iguana_msgvout *msg)
{
    int32_t len = 0;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->value),&msg->value);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->pk_scriptlen);
    if ( rwflag == 0 )
        msg->pk_script = mycalloc('s',1,msg->pk_scriptlen);
    len += iguana_rwmem(rwflag,&serialized[len],msg->pk_scriptlen,msg->pk_script);
    //printf("(%.8f scriptlen.%d) ",dstr(msg->value),msg->pk_scriptlen);
    //int i; for (i=0; i<msg->pk_scriptlen; i++)
    //    printf("%02x",msg->pk_script[i]);
    //printf("\n");
    return(len);
}

int32_t iguana_rwtx(int32_t rwflag,uint8_t *serialized,struct iguana_msgtx *msg,int32_t maxsize,bits256 *txidp,int32_t height,int32_t hastimestamp)
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
            msg->vins = mycalloc('v',msg->tx_in,sizeof(*msg->vins));
        for (i=0; i<msg->tx_in; i++)
            len += iguana_rwvin(rwflag,&serialized[len],&msg->vins[i]);
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
            msg->vouts = mycalloc('v',msg->tx_out,sizeof(*msg->vouts));
        for (i=0; i<msg->tx_out; i++)
            len += iguana_rwvout(rwflag,&serialized[len],&msg->vouts[i]);
    }
    else
    {
        printf("invalid tx_out.%d\n",msg->tx_out);
        return(-1);
    }
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->lock_time),&msg->lock_time);
    *txidp = bits256_doublesha256(txidstr,txstart,len);
    //printf("txid.(%s) len.%d\n",bits256_str(*txidp),len);
    msg->allocsize = len;
    Tx_allocated++, Tx_allocsize += len;
    if ( ((Tx_allocated + Tx_freed) % 10000000) == 0 )
        printf("h.%u len.%d (%llu - %llu) %lld (%llu - %llu)\n",height,len,(long long)Tx_allocated,(long long)Tx_freed,(long long)(Tx_allocated - Tx_freed),(long long)Tx_allocsize,(long long)Tx_freesize);
    return(len);
}

void iguana_freetx(struct iguana_msgtx *tx,int32_t n)
{
    int32_t i,j; struct iguana_msgtx *origtx = tx;
    for (j=0; j<n; j++,tx++)
    {
        Tx_freed++, Tx_freesize += tx->allocsize;
        if ( tx->vins != 0 )
        {
            for (i=0; i<tx->tx_in; i++)
                if ( tx->vins[i].script != 0 )
                    myfree(tx->vins[i].script,tx->vins[i].scriptlen);
            myfree(tx->vins,tx->tx_in * sizeof(*tx->vins));
        }
        if ( tx->vouts != 0 )
        {
            for (i=0; i<tx->tx_out; i++)
                if ( tx->vouts[i].pk_script != 0 )
                    myfree(tx->vouts[i].pk_script,tx->vouts[i].pk_scriptlen);
            myfree(tx->vouts,tx->tx_out * sizeof(*tx->vouts));
        }
    }
    myfree(origtx,sizeof(*origtx) * n);
}

struct iguana_msgtx *iguana_gentxarray(struct iguana_info *coin,int32_t *lenp,struct iguana_block *block,uint8_t *data,int32_t datalen,uint8_t extra[256])
{
    struct iguana_msgtx *tx; bits256 hash2; struct iguana_msgblock msg; int32_t i,n,len;
    memset(&msg,0,sizeof(msg));
    len = iguana_rwblock(0,&hash2,data,&msg);
    iguana_convblock(block,&msg,hash2,block->height,block->L.numtxids,block->L.numunspents,block->L.numspends,block->L.PoW);
    block->txn_count = msg.txn_count;
    block->height = iguana_setdependencies(coin,block);
    //printf("iguana_gentxarray block %s prev.(%s): height.%d firsttxidind.%d firstvout.%d firstvin.%d PoW %f numtx.%d\n",bits256_str2(hash2),bits256_str(msg.H.prev_block),block->height,block->L.firsttxidind,block->L.firstvout,block->L.firstvin,block->L.PoW,msg.txn_count);
    iguana_convblock(block,&msg,hash2,block->height,block->L.numtxids,block->L.numunspents,block->L.numspends,block->L.PoW);
    tx = mycalloc('t',msg.txn_count,sizeof(*tx));
    for (i=0; i<msg.txn_count; i++)
    {
        if ( (n= iguana_rwtx(0,&data[len],&tx[i],datalen - len,&tx[i].txid,block->height,coin->chain->hastimestamp)) < 0 )
            break;
        len += n;
    }
    if ( coin->chain->hastimestamp != 0 && len != datalen && data[len] == (datalen - len - 1) )
    {
        //printf("\n>>>>>>>>>>> len.%d vs datalen.%d [%d]\n",len,datalen,data[len]);
        memcpy(extra,&data[len],datalen-len);
        len += (datalen-len);
    }
    *lenp = len;
    return(tx);
}

struct iguana_bundlereq *iguana_bundlereq(struct iguana_info *coin,struct iguana_peer *addr,int32_t type,int32_t datalen)
{
    struct iguana_bundlereq *req; int32_t allocsize;
    allocsize = (uint32_t)sizeof(*req) + datalen;
    req = mycalloc(type,1,allocsize);
    req->allocsize = allocsize;
    req->datalen = datalen;
    req->addr = addr;
    req->coin = coin;
    req->type = type;
    return(req);
}

void iguana_gottxidsM(struct iguana_info *coin,struct iguana_peer *addr,bits256 *txids,int32_t n)
{
    struct iguana_bundlereq *req;
    printf("got %d txids from %s\n",n,addr->ipaddr);
    req = iguana_bundlereq(coin,addr,'T',0);
    req->hashes = txids, req->n = n;
    queue_enqueue("bundlesQ",&coin->bundlesQ,&req->DL,0);
}

void iguana_gotunconfirmedM(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_msgtx *tx,uint8_t *data,int32_t datalen)
{
    struct iguana_bundlereq *req;
    printf("%s unconfirmed.%s\n",addr->ipaddr,bits256_str(tx->txid));
    req = iguana_bundlereq(coin,addr,'U',datalen);
    req->n = datalen;
    memcpy(req->serialized,data,datalen);
    iguana_freetx(tx,1);
    queue_enqueue("bundlesQ",&coin->bundlesQ,&req->DL,0);
}

void iguana_gotblockM(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_block *block,struct iguana_msgtx *txarray,int32_t numtx,uint8_t *data,int32_t datalen,uint8_t extra[256])
{
    struct iguana_bundlereq *req; int32_t i;
    if ( 0 )
    {
        for (i=0; i<extra[0]; i++)
            if ( extra[i] != 0 )
                break;
        if ( i != extra[0] )
        {
            for (i=0; i<extra[0]; i++)
                printf("%02x ",extra[i]);
            printf("extra\n");
        }
    }
    if ( addr != 0 )
    {
        if ( addr->pendblocks > 0 )
            addr->pendblocks--;
        addr->lastblockrecv = (uint32_t)time(NULL);
        addr->recvblocks += 1.;
        addr->recvtotal += datalen;
    }
    coin->recvcount++;
    coin->recvtime = (uint32_t)time(NULL);
    req = iguana_bundlereq(coin,addr,'B',datalen);
    req->blocks = block, req->n = datalen;
    memcpy(req->serialized,data,datalen);
    //printf("test emit txarray[%d] %p\n",numtx,block);
    block->txn_count = req->numtx = numtx;
    iguana_freetx(txarray,numtx);
    queue_enqueue("bundlesQ",&coin->bundlesQ,&req->DL,0);
}

void iguana_gotheadersM(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_block *blocks,int32_t n)
{
    struct iguana_bundlereq *req;
    if ( addr != 0 )
    {
        addr->recvhdrs++;
        if ( addr->pendhdrs > 0 )
            addr->pendhdrs--;
        //printf("%s blocks[%d] ht.%d gotheaders pend.%d %.0f\n",addr->ipaddr,n,blocks[0].height,addr->pendhdrs,milliseconds());
    }
    req = iguana_bundlereq(coin,addr,'H',0);
    req->blocks = blocks, req->n = n;
    queue_enqueue("bundlesQ",&coin->bundlesQ,&req->DL,0);
}

void iguana_gotblockhashesM(struct iguana_info *coin,struct iguana_peer *addr,bits256 *blockhashes,int32_t n)
{
    struct iguana_bundlereq *req;
    if ( addr != 0 )
    {
        addr->recvhdrs++;
        if ( addr->pendhdrs > 0 )
            addr->pendhdrs--;
    }
    req = iguana_bundlereq(coin,addr,'S',0);
    req->hashes = blockhashes, req->n = n;
    //printf("bundlesQ blockhashes.%p[%d]\n",blockhashes,n);
    queue_enqueue("bundlesQ",&coin->bundlesQ,&req->DL,0);
}

struct iguana_rawtx { bits256 txid; uint16_t numvouts,numvins; uint8_t rmd160[20]; };

int32_t iguana_emittx(struct iguana_info *coin,FILE *fp,struct iguana_block *block,struct iguana_msgtx *tx,int32_t txi,uint32_t *numvoutsp,uint32_t *numvinsp,int64_t *outputp)
{
    int32_t blocknum,i; int64_t reward; uint16_t s; struct iguana_rawtx rawtx; uint8_t rmd160[20],buf[64];
    struct iguana_msgvin *vin;
    blocknum = block->hh.itemind;
    memset(&rawtx,0,sizeof(rawtx));
    rawtx.txid = tx->txid;
    rawtx.numvouts = tx->tx_out, rawtx.numvins = tx->tx_in;
    if ( (blocknum == 91842 || blocknum == 91880) && txi == 0 && strcmp(coin->name,"bitcoin") == 0 )
        rawtx.txid.ulongs[0] ^= blocknum;
    //printf("%d: tx.%p %p[numvouts.%d] %p[numvins.%d]\n",block->hh.itemind,tx,tx->vouts,tx->tx_out,tx->vins,tx->tx_in);
    if ( fwrite(&rawtx,1,sizeof(rawtx),fp) == sizeof(rawtx) )
    {
        for (i=0; i<rawtx.numvouts; i++)
        {
            iguana_calcrmd160(coin,rmd160,tx->vouts[i].pk_script,tx->vouts[i].pk_scriptlen,rawtx.txid);
            memcpy(buf,&tx->vouts[i].value,sizeof(tx->vouts[i].value));
            memcpy(&buf[sizeof(tx->vouts[i].value)],rmd160,sizeof(rmd160));
            if ( fwrite(buf,1,sizeof(rmd160)+sizeof(tx->vouts[i].value),fp) == sizeof(rmd160)+sizeof(tx->vouts[i].value) )
            {
                (*numvoutsp)++;
                (*outputp) += tx->vouts[i].value;
            } else printf("error writing txi.%d vout.%d\n",txi,i);
        }
        for (i=0; i<rawtx.numvins; i++)
        {
            vin = &tx->vins[i];
            if ( bits256_nonz(vin->prev_hash) == 0 )
            {
                if ( i == 0 && (int32_t)vin->prev_vout < 0 )
                {
                    reward = iguana_miningreward(coin,blocknum);
                    //printf("reward %.8f\n",dstr(reward));
                    (*outputp) += reward;
                } else printf("unexpected prevout.%d\n",vin->prev_vout), getchar();
                continue;
            }
            memcpy(buf,vin->prev_hash.bytes,sizeof(vin->prev_hash));
            s = vin->prev_vout;
            memcpy(&buf[sizeof(vin->prev_hash)],&s,sizeof(s));
            //printf("do spend.%s\n",bits256_str(vin->prev_hash));
            if ( fwrite(buf,1,sizeof(bits256)+sizeof(s),fp) == sizeof(bits256)+sizeof(s) )
                (*numvinsp)++;
            else printf("error writing txi.%d vin.%d\n",txi,i);
        }
        return(0);
    }
    else printf("error writing txi.%d blocknum.%d\n",txi,blocknum);
    return(-1);
}

void iguana_emittxarray(struct iguana_info *coin,FILE *fp,struct iguana_block *block,struct iguana_msgtx *txarray,int32_t numtx)
{
    uint32_t i,numvouts,numvins; int64_t credits; long fpos,endpos;
    if ( fp != 0 && block != 0 )
    {
        //printf("%d/%d: txarray.%p, numtx.%d bp.%p\n",block->hh.itemind,block->hh.itemind,txarray,numtx,bp);
        fpos = ftell(fp);
        credits = numvouts = numvins = 0;
        for (i=0; i<numtx; i++)
            iguana_emittx(coin,fp,block,&txarray[i],i,&numvouts,&numvins,&credits);
        endpos = ftell(fp);
        fseek(fp,fpos,SEEK_SET);
        block->L.supply = credits;
        block->txn_count = numtx;
        block->numvouts = numvouts, block->numvins = numvins;
        block->L.numtxids = numtx, block->L.numunspents = numvouts, block->L.numspends = numvins;
        if ( fwrite(block,1,sizeof(*block),fp) != sizeof(*block) )
            printf("iguana_emittxarray: error writing block.%d\n",block->height);
        fseek(fp,endpos,SEEK_SET);
    }
}

int32_t iguana_maptxdata(struct iguana_info *coin,struct iguana_mappedptr *M,struct iguana_bundle *bp,char *fname)
{
    void *fileptr = 0; int32_t i; uint32_t *offsets; struct iguana_block *block;
    if ( (fileptr= iguana_mappedptr(0,M,0,0,fname)) != 0 )
    {
        offsets = fileptr;
        for (i=0; i<bp->n; i++)
        {
            if ( (block= bp->blocks[i]) != 0 )
            {
                if ( block->txdata != 0 )
                {
                    if ( block->mapped == 0 )
                    {
                        printf("[%d].%d free txdata.%d %p\n",bp->hdrsi,i,((struct iguana_bundlereq *)block->txdata)->allocsize,block->txdata);
                        myfree(block->txdata,((struct iguana_bundlereq *)block->txdata)->allocsize);
                        block->txdata = 0;
                        block->mapped = 0;
                    }
                }
                if ( i < coin->chain->bundlesize )
                {
                    block->txdata = (void *)((long)fileptr + offsets[i]);
                    block->mapped = 1;
                }
            }
            else if ( i < coin->chain->bundlesize )
                printf("iguana_maptxdata cant find block[%d]\n",i);
        }
        return(i < coin->chain->bundlesize ? i : coin->chain->bundlesize);
    }
    printf("error mapping (%s)\n",fname);
    return(-1);
}

void iguana_emittxdata(struct iguana_info *coin,struct iguana_bundle *emitbp)
{
    FILE *fp; char fname[512]; uint8_t extra[256]; uint32_t offsets[_IGUANA_HDRSCOUNT+1];
    struct iguana_msgtx *txarray,*tx; struct iguana_bundlereq *req; struct iguana_mappedptr M;
    int32_t i,j,bundleheight,len2,height,numtx,n; long len; struct iguana_block *block;
    if ( emitbp == 0 )
        return;
    sprintf(fname,"tmp/%s/txdata.%d",coin->symbol,emitbp->bundleheight);
    if ( (fp= fopen(fname,"wb")) != 0 )
    {
        bundleheight = emitbp->bundleheight;
        for (i=n=0; i<emitbp->n&&i<coin->chain->bundlesize; i++)
            if ( (block= emitbp->blocks[i]) != 0 && block->txdata != 0 && block->mapped == 0 )
                n++;
        if ( n != emitbp->n && n != coin->chain->bundlesize )
            printf("iguana_emittxdata: WARNING n.%d != bundlesize.%d bundlesize.%d\n",n,emitbp->n,coin->chain->bundlesize);
        memset(offsets,0,sizeof(offsets));
        if ( (len= fwrite(offsets,sizeof(*offsets),n+1,fp)) != n+1 )
            printf("%s: error writing blank offsets len.%ld != %d\n",fname,len,n+1);
        for (i=0; i<n; i++)
        {
            offsets[i] = (uint32_t)ftell(fp);
            height = (bundleheight + i);
            if ( (block= emitbp->blocks[i]) != 0 )
            {
                if ( (req= block->txdata) != 0 && (numtx= block->txn_count) > 0 )
                {
                    if ( 0 && fwrite(req->serialized,1,req->n,fp) != req->n )
                        printf("error writing serialized data.%d\n",req->n);
                    if ( 0 && (txarray= iguana_gentxarray(coin,&len2,block,req->serialized,req->n,extra)) != 0 )
                    {
                        tx = txarray;
                        for (j=0; j<numtx; j++,tx++)
                            printf("(%p[%d] %p[%d]) ",tx->vouts,tx->tx_out,tx->vins,tx->tx_in);
                        printf("emit.%d txarray.%p[%d]\n",i,txarray,numtx);
                        iguana_emittxarray(coin,fp,block,txarray,numtx);
                        iguana_freetx(txarray,numtx);
                    }
                } else printf("emittxdata: unexpected missing txarray[%d]\n",i);
            } else printf("emittxdata: error with recvblockptr[%d]\n",emitbp->bundleheight + i);
        }
        offsets[i] = (uint32_t)ftell(fp);
        rewind(fp);
        if ( (len= fwrite(offsets,sizeof(*offsets),n+1,fp)) != n+1 )
            printf("%s: error writing offsets len.%ld != %d\n",fname,len,n+1);
        fclose(fp), fp = 0;
        memset(&M,0,sizeof(M));
        //if ( iguana_maptxdata(coin,&M,emitbp,fname) != n )
        //    printf("emit error mapping n.%d height.%d\n",n,bundleheight);
        //else
        {
            //if ( emitbp->blockhashes != 0 )
            //    myfree(emitbp->blockhashes,sizeof(*emitbp->blockhashes) * emitbp->n);
            //emitbp->blockhashes = 0;
        }
    }
}

void iguana_emitQ(struct iguana_info *coin,struct iguana_bundle *bp)
{
    bp->coin = coin;
    bp->type = 'E';
    queue_enqueue("emitQ",&helperQ,&bp->DL,0);
}

void iguana_txdataQ(struct iguana_info *coin,struct iguana_bundlereq *req)
{
    req->coin = coin;
    req->type = 'Q';
    queue_enqueue("txdataQ",&helperQ,&req->DL,0);
}

void iguana_helper(void *arg)
{
    FILE *fp = 0; long endpos = 0; char fname[512]; int32_t flag;
    struct iguana_bundle *bp; struct iguana_bundlereq *req;
    sprintf(fname,"tmp/helper.%d",*(int32_t *)arg);
    printf("start helper %s fp.%p\n",fname,fp);
    while ( 1 )
    {
        flag = 0;
        if ( (bp= queue_dequeue(&helperQ,0)) != 0 )
        {
            if ( bp->type == 'Q' )
            {
                req = (struct iguana_bundlereq *)bp;
                //printf("START save tmp txdata %p [%d].%d datalen.%d\n",req->argbp,req->argbp!=0?req->argbp->hdrsi:-1,req->argbundlei,req->datalen);
                if ( fp == 0 )
                {
                    if ( (fp= fopen(fname,"rb+")) == 0 )
                        fp = fopen(fname,"wb");
                    fseek(fp,endpos,SEEK_SET);
                }
                if ( fp != 0 )
                {
                    if ( fwrite(req->serialized,1,req->datalen,fp) != req->datalen )
                        printf("error writing [%d].%d datalen.%d\n",req->argbp!=0?req->argbp->hdrsi:-1,req->argbundlei,req->datalen);
                    endpos = ftell(fp);
                    fclose(fp);
                    fp = 0;
                }
                myfree(req,req->allocsize);
            }
            else if ( bp->type == 'E' )
            {
                fflush(fp);
                myallocated();
                iguana_emittxdata(bp->coin,bp);
                myallocated();
                if ( bp->coin != 0 )
                {
                    if ( bp->coin->estsize > bp->coin->MAXRECVCACHE*.9 && bp->coin->MAXBUNDLES > _IGUANA_MAXBUNDLES )
                        bp->coin->MAXBUNDLES--;
                    else if ( bp->coin->activebundles >= bp->coin->MAXBUNDLES && bp->coin->estsize < bp->coin->MAXRECVCACHE*.5 )
                        bp->coin->MAXBUNDLES++;
                    bp->coin->numemitted++;
                }
            }
            else
            {
                printf("iguana_helper: unsupported type.%c %d %p\n",bp->type,bp->type,bp);
            }
            flag++;
            //printf("FINISH emittxdata\n");
        }
        if ( flag == 0 )
            usleep(10000);
    }
}

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


int32_t iguana_needhdrs(struct iguana_info *coin)
{
    if ( coin->longestchain == 0 || coin->blocks.hashblocks < coin->longestchain-coin->chain->bundlesize )
        return(1);
    else return(0);
}

void iguana_recvalloc(struct iguana_info *coin,int32_t numitems)
{
    //int32_t numbundles;
    coin->bundleready = myrealloc('W',coin->bundleready,coin->bundleready==0?0:coin->blocks.maxbits/coin->chain->bundlesize+1,numitems/coin->chain->bundlesize+1);
    coin->blocks.ptrs = myrealloc('W',coin->blocks.ptrs,coin->blocks.ptrs==0?0:coin->blocks.maxbits * sizeof(*coin->blocks.ptrs),numitems * sizeof(*coin->blocks.ptrs));
    printf("realloc waitingbits.%d -> %d\n",coin->blocks.maxbits,numitems);
    coin->blocks.maxbits = numitems;
}

void *iguana_blockptr(struct iguana_info *coin,int32_t height)
{
    struct iguana_block *block;
    if ( height < 0 || height >= coin->blocks.maxbits )
        return(0);
    if ( height == 0 )
        return(coin->chain->genesis_hashdata);
    if ( (block= coin->blocks.ptrs[height]) != 0 )
        return(block->txdata);
    else return(0);
}

int32_t iguana_avail(struct iguana_info *coin,int32_t height,int32_t n)
{
    int32_t i,nonz = 0;
    for (i=0; i<n; i++)
        if ( iguana_blockptr(coin,height+i) != 0 )
            nonz++;
    return(nonz);
}

int32_t iguana_bundleready(struct iguana_info *coin,int32_t height)
{
    int32_t i,num = coin->chain->bundlesize;
    if ( GETBIT(coin->bundleready,height/num) != 0 )
        return(1);
    for (i=0; i<num; i++)
        if ( iguana_havehash(coin,height+i) <= 0 )
        return(0);
    SETBIT(coin->bundleready,height/num);
    return(1);
}

int32_t iguana_savehdrs(struct iguana_info *coin)
{
    int32_t height,iter,valid,retval = 0; char fname[512],tmpfname[512],oldfname[512]; bits256 hash2; FILE *fp;
    sprintf(oldfname,"%s_oldhdrs.txt",coin->symbol);
    sprintf(tmpfname,"tmp/%s/hdrs.txt",coin->symbol);
    sprintf(fname,"%s_hdrs.txt",coin->symbol);
    /*if ( (fp= fopen(fname,"r")) != 0 )
    {
        if ( fgets(line,sizeof(line),fp) > 0 )
        {
            line[strlen(line)-1] = 0;
            if ( atoi(line) > coin->blocks.hashblocks )
            {
                //printf("skip save since %s has %d\n",fname,atoi(line));
                fclose(fp);
                return(0);
            }
        }
        fclose(fp);
    }*/
    if ( (fp= fopen(tmpfname,"w")) != 0 )
    {
        fprintf(fp,"%d\n",coin->blocks.hashblocks);
        for (height=0; height<=coin->blocks.hashblocks; height+=coin->chain->bundlesize)
        {
            for (iter=0; iter<2; iter++)
            {
                hash2 = iguana_blockhash(coin,&valid,height+iter);
                if ( bits256_nonz(hash2) > 0 )
                {
                    fprintf(fp,"%d %s\n",height+iter,bits256_str(hash2));
                    retval = height+iter;
                }
                if ( coin->chain->hasheaders != 0 )
                    break;
            }
        }
        //printf("new hdrs.txt %ld vs (%s) %ld\n",ftell(fp),fname,(long)iguana_filesize(fname));
        if ( ftell(fp) > iguana_filesize(fname) )
        {
            printf("new hdrs.txt %ld vs (%s) %ld\n",ftell(fp),fname,(long)iguana_filesize(fname));
            fclose(fp);
            iguana_renamefile(fname,oldfname);
            iguana_copyfile(tmpfname,fname,1);
        } else fclose(fp);
    }
    return(retval);
}

void iguana_parseline(struct iguana_info *coin,int32_t iter,FILE *fp)
{
    int32_t j,k,m,c,height; bits256 hash2; char checkstr[1024],line[1024]; struct iguana_peer *addr;
    m = 0;
    while ( fgets(line,sizeof(line),fp) > 0 )
    {
        j = (int32_t)strlen(line) - 1;
        line[j] = 0;
        //printf("parse line.(%s)\n",line);
        if ( iter == 0 )
        {
            if ( m < coin->MAXPEERS )
            {
                addr = &coin->peers.active[m++];
                iguana_initpeer(coin,addr,(uint32_t)calc_ipbits(line));
                printf("call initpeer.(%s)\n",addr->ipaddr);
                iguana_launch("connection",iguana_startconnection,addr,IGUANA_CONNTHREAD);
            }
        }
        else
        {
            for (k=height=0; k<j-1; k++)
            {
                if ( (c= line[k]) == ' ' )
                    break;
                else if ( c >= '0' && c <= '9' )
                    height = (height * 10) + (line[k] - '0');
                else break;
            }
            //printf("parseline: k.%d %d keight.%d m.%d \n",k,line[k],height,m);
            if ( line[k] == ' ' )
            {
                decode_hex(hash2.bytes,sizeof(hash2),line+k+1);
                init_hexbytes_noT(checkstr,hash2.bytes,sizeof(hash2));
                if ( strcmp(checkstr,line+k+1) == 0 )
                {
                    printf("add bundle.%d (%s)\n",height,bits256_str(hash2));
                    if ( (height % coin->chain->bundlesize) == 0 )
                    {
                        if ( height > coin->blocks.maxbits-coin->chain->bundlesize*10 )
                            iguana_recvalloc(coin,height + coin->chain->bundlesize*100);
                        if ( height <= coin->chain->bundlesize*coin->bundleswidth )
                            queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(checkstr),1);
                        queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(checkstr),1);
                    }
                    iguana_blockhashset(coin,height,hash2,0);
                }
            }
        }
    }
}

/*int32_t iguana_setwaitstart(struct iguana_info *coin,int32_t height)
{
    if ( coin->R.waitstart[height] == 0 )
        coin->R.numwaiting++;
    coin->R.waitstart[height] = (uint32_t)time(NULL);
    SETBIT(coin->R.waitingbits,height);
    return(coin->R.numwaiting);
}*/

struct iguana_blockreq { struct queueitem DL; bits256 hash2,*blockhashes; int32_t n,height; };
int32_t iguana_queueblock(struct iguana_info *coin,int32_t height,bits256 hash2,int32_t priority)
{
    queue_t *Q; char *str; struct iguana_blockreq *req;
    if ( bits256_nonz(hash2) == 0 )
    {
        printf("cant queue zerohash height.%d\n",height), getchar();
        return(-1);
    }
    if ( height < 0 || (height >= coin->blocks.recvblocks && iguana_blockptr(coin,height) == 0) )
    {
        if ( priority != 0 )
            str = "priorityQ", Q = &coin->priorityQ;
        else //if ( GETBIT(coin->R.waitingbits,height) == 0 )
            str = "blocksQ", Q = &coin->blocksQ;
        //else str = "already pending", Q = 0;
        if ( Q != 0 )
        {
            req = mycalloc('r',1,sizeof(*req));
            req->hash2 = hash2;
            req->height = height;
            if ( (height % 1000) == 0 )
                printf("%s %d %s recv.%d numranked.%d\n",str,height,bits256_str(hash2),coin->blocks.recvblocks,coin->peers.numranked);
            queue_enqueue(str,Q,&req->DL,0);
            return(1);
        }
    }
    //printf("iguana_queueblock skip.%d %s recvblocks.%d %p GETBIT.%d\n",height,bits256_str(hash2),coin->blocks.recvblocks,iguana_recvblock(coin,height),GETBIT(coin->R.waitingbits,height));
    return(0);
}

int32_t iguana_pollQs(struct iguana_info *coin,struct iguana_peer *addr)
{
    uint8_t serialized[sizeof(struct iguana_msghdr) + sizeof(uint32_t)*32 + sizeof(bits256)];
    char *hashstr=0,hexstr[65]; bits256 hash2; int32_t height=-1,datalen,flag = 0;
    struct iguana_blockreq *req=0;
    if ( iguana_needhdrs(coin) != 0 && addr->pendhdrs == 0 && (hashstr= queue_dequeue(&coin->hdrsQ,1)) != 0 )
    {
        if ( (datalen= iguana_gethdrs(coin,serialized,coin->chain->gethdrsmsg,hashstr)) > 0 )
        {
            decode_hex(hash2.bytes,sizeof(hash2),hashstr);
            //printf("%s request hdr.(%s) %d pend.%d\n",addr->ipaddr,hashstr,iguana_blockheight(coin,hash2),addr->pendhdrs);
            iguana_send(coin,addr,serialized,datalen,&addr->sleeptime);
            addr->pendhdrs++;
            flag++;
        } else printf("datalen.%d from gethdrs\n",datalen);
        free_queueitem(hashstr);
        hashstr = 0;
    }
    if ( ((req= queue_dequeue(&coin->priorityQ,0)) != 0 || (req= queue_dequeue(&coin->blocksQ,0)) != 0) )
    {
        hash2 = req->hash2;
        height = iguana_blockheight(coin,hash2);
        if ( height != req->height )
        {
            printf("blocksQ ht.%d vs %d dequeued.(%s) for %s\n",req->height,height,bits256_str(hash2),addr->ipaddr);
            myfree(req,sizeof(*req));
            return(0);
        }
        if ( height >= 0 && (height < coin->blocks.recvblocks || iguana_blockptr(coin,height) != 0) )
        {
            printf("skip.%d vs recvblocks.%d %p\n",height,coin->blocks.recvblocks,iguana_blockptr(coin,height));
            myfree(req,sizeof(*req));
        }
        else
        {
            init_hexbytes_noT(hexstr,hash2.bytes,sizeof(hash2));
            if ( (datalen= iguana_getdata(coin,serialized,MSG_BLOCK,hexstr)) > 0 )
            {
                //printf("%s %s REQ BLOCK.%d\n",addr->ipaddr,hexstr,iguana_blockheight(coin,hash2));
                iguana_send(coin,addr,serialized,datalen,&addr->sleeptime);
                //if ( height >= 0 )
                //    iguana_setwaitstart(coin,height);
                addr->pendblocks++;
                addr->pendtime = (uint32_t)time(NULL);
                flag++;
                myfree(req,sizeof(*req));
            } else printf("error constructing request %s.%d\n",hexstr,height);
        }
    }
    return(flag);
}

void iguana_gotdata(struct iguana_info *coin,struct iguana_peer *addr,int32_t height,bits256 hash2,int32_t i,int32_t n)
{
    int32_t h,flag = 0;
    if ( height >= 0 && bits256_nonz(hash2) > 0 )
    {
        //printf("gotdata.%d %s i.%d n.%d\n",height,bits256_str(hash2),i,n);
        if ( (height % coin->chain->bundlesize) == 0 )
        {
            //iguana_bundleinit(coin,height,hash2);
            h = height - coin->chain->bundlesize;
            while ( iguana_bundleready(coin,h) > 0 )
            {
                h += coin->chain->bundlesize;
                //coin->R.tophash2 = iguana_blockhash(coin,&valid,h);
                //coin->R.topheight = h;
                flag++;
            }
            if ( flag != 0 )
                iguana_savehdrs(coin);
        }
        if ( coin->chain->hasheaders == 0 && (height % coin->chain->bundlesize) == 1 )
            iguana_queueblock(coin,height,hash2,1);
    }
    if ( addr != 0 && height > addr->height && height < coin->longestchain )
    {
        iguana_set_iAddrheight(coin,addr->ipbits,height);
        addr->height = height;
    }
}

int32_t iguana_bundleheight(struct iguana_info *coin,struct iguana_block *block)
{
    int32_t height;
    if ( (height= iguana_blockheight(coin,block->hash2)) < 0 )
    {
        if ( (height= iguana_blockheight(coin,block->prev_block)) < 0 )
        {
            iguana_blockhashset(coin,-1,block->hash2,0);
            iguana_blockhashset(coin,-1,block->prev_block,0);
        }
        else
        {
            height++;
            iguana_blockhashset(coin,height,block->hash2,0);
        }
    } else iguana_blockhashset(coin,height,block->hash2,0); // increments matches
    return(height);
}

struct iguana_bundlereq *iguana_recvhashes(struct iguana_info *coin,struct iguana_bundlereq *req,bits256 *blockhashes,int32_t n)
{
 /*   int32_t height;
    height = iguana_blockheight(coin,blockhashes[0]);
    if ( n > 2 && iguana_needhdrs(coin) > 0 )
    {
        //printf("got blockhashes[%d] %s height.%d\n",n,bits256_str(blockhashes[0]),height);
        if ( height >= 0 )
        {
            for (j=0; j<n && j<coin->chain->bundlesize && height+j<coin->longestchain; j++)
            {
                iguana_bundleset(coin,height+j,blockhashes[j]);
                iguana_gotdata(coin,0,height+j,blockhashes[j],j,n);
            }
        }
        else
        {
            iguana_queueblock(coin,-1,blockhashes[0],1);
            for (i=0; i<coin->numpendings; i++)
                if ( memcmp(coin->pendings[i].blockhashes[0].bytes,blockhashes[0].bytes,sizeof(bits256)) == 0 )
                    break;
            if ( i == coin->numpendings )
            {
                if ( coin->numpendings < sizeof(coin->pendings)/sizeof(*coin->pendings) )
                {
                    coin->pendings[coin->numpendings].blockhashes = blockhashes;
                    coin->pendings[coin->numpendings].n = n;
                    coin->pendings[coin->numpendings].starttime = (uint32_t)time(NULL);
                    coin->numpendings++;
                    printf("ADD to numpendings.%d priority.(%s) n.%d\n",coin->numpendings,bits256_str(blockhashes[0]),n);
                    blockhashes = 0;
                } else printf("updatebundles: overflowed pendings\n");
            }
        }
    }*/
    return(req);
}

struct iguana_bundlereq *iguana_recvblock(struct iguana_info *coin,struct iguana_bundlereq *req,struct iguana_block *block,uint8_t *data,int32_t datalen)
{
   /* int32_t height;
    //printf("%s got block.(%s) height.%d\n",req->addr!=0?req->addr->ipaddr:"local",bits256_str(block->hash2),height);
    if ( (height= iguana_bundleheight(coin,block)) > 0 )
    {
        if ( (ptrp= iguana_blockptrptr(coin,&blocki,height)) != 0 )
        {
            if ( (*ptrp) == 0 )
            {
                //printf("height.%d tx.%p blocki.%d txarray.%p[%d] (%p[%d] %p[%d])\n",height,&txarray[0],blocki,txarray,numtx,txarray[0].vouts,txarray[0].tx_out,txarray[0].vins,txarray[0].tx_in);
                (*ptrp) = (void *)txarray;
                bp->numtxs[blocki] = numtx;
                if ( bp->emitstart == 0 && ++bp->numvalid >= bp->num )
                {
                    bp->emitstart = (uint32_t)time(NULL);
                    iguana_emittxdata(coin,bp);
                    //printf("queue txarray.%p[%d]\n",txarray,numtx);
                    //queue_enqueue("emitQ",&coin->emitQ,&bp->DL,0);
                }
                //txarray = 0;
            }
        }
        else printf("cant get ptrp.%d\n",height), getchar();
        iguana_gotdata(coin,req->addr,height,block->hash2,0,0);
        if ( bp != 0 && iguana_bundleready(coin,height-1) <= 0 )
        {
            printf("check for pendings.%d height.%d\n",coin->numpendings,height);
            if ( height == coin->blocks.hwmheight )
                (*newhwmp)++;
            for (i=0; i<coin->numpendings; i++)
                if ( memcmp(coin->pendings[i].blockhashes[0].bytes,block->hash2.bytes,sizeof(block->hash2)) == 0 )
                {
                    blockhashes = coin->pendings[i].blockhashes;
                    n = coin->pendings[i].n;
                    printf("pending[%d].%d bundlesets[%d] %d %s\n",i,coin->numpendings,n,height,bits256_str(blockhashes[0]));
                    for (j=0; j<n && j<coin->chain->bundlesize && height+j<coin->longestchain; j++)
                    {
                        iguana_bundleset(coin,height+j,blockhashes[j]);
                        iguana_gotdata(coin,0,height+j,blockhashes[j],j,n);
                    }
                    myfree(blockhashes,n * sizeof(*blockhashes));
                    coin->pendings[i] = coin->pendings[--coin->numpendings];
                    break;
                }
            //  queue tx for processing
        }
        else
        {
            // probably new block
            //printf("couldnt find.(%s)\n",bits256_str(block->hash2));
        }
    }*/
    return(req);
}

struct iguana_bundlereq *iguana_recvblockhdrs(struct iguana_info *coin,struct iguana_bundlereq *req,struct iguana_block *blocks,int32_t n)
{
    if ( blocks == 0 )
        return(req);
  /*  if ( iguana_bundlefindprev(coin,&height,blocks[0].prev_block) != 0 && height >= 0 )
    {
        //printf(">>>>>> found %s height.%d n.%d\n",bits256_str(blocks[0].prev_block),height,n);
        height++;
        for (i=0; i<n && i<coin->chain->bundlesize && height<coin->longestchain; i++,height++)
        {
            //printf("i.%d height.%d\n",i,height);
            iguana_bundleset(coin,height,blocks[i].hash2);
            iguana_gotdata(coin,req->addr,height,blocks[i].hash2,i,n);
            if ( height >= coin->blocks.hwmheight )
            {
                if ( height == coin->blocks.hwmheight )
                    (*newhwmp)++;
                if ( (block= iguana_block(coin,height)) != 0 )
                    iguana_mergeblock(block,&blocks[i]);
                else printf("unexpected null block at height.%d\n",height), getchar();
            }
            else
            {
                // verify it doesnt trigger reorg (and is recent enough!)
            }
        }
    } else printf("unexpected bundlefind error %s height.%d\n",bits256_str(blocks[0].prev_block),height), getchar();
   */
    return(req);
}

struct iguana_bundlereq *iguana_recvblockhashes(struct iguana_info *coin,struct iguana_bundlereq *req,bits256 *blockhashes,int32_t n)
{
    return(req);
}

struct iguana_bundlereq *iguana_recvtxids(struct iguana_info *coin,struct iguana_bundlereq *req,bits256 *txids,int32_t n)
{
    return(req);
}

struct iguana_bundlereq *iguana_recvunconfirmed(struct iguana_info *coin,struct iguana_bundlereq *req,uint8_t *data,int32_t datalen)
{
    return(req);
}

int32_t iguana_processbundlesQ(struct iguana_info *coin,int32_t *newhwmp) // single threaded
{
    int32_t flag = 0; struct iguana_bundlereq *req;
    *newhwmp = 0;
    while ( (req= queue_dequeue(&coin->bundlesQ,0)) != 0 )
    {
        //printf("bundlesQ.%p type.%c n.%d\n",req,req->type,req->n);
        if ( req->type == 'B' ) // one block with all txdata
        {
            if ( (req= iguana_recvblock(coin,req,req->blocks,req->serialized,req->n)) != 0 )
            {
                if ( req->blocks != 0 )
                    myfree(req->blocks,sizeof(*req->blocks));
                myfree(req,req->allocsize);
            }
        }
        else if ( req->type == 'H' ) // blockhdrs (doesnt have txn_count!)
        {
            if ( (req= iguana_recvblockhdrs(coin,req,req->blocks,req->n)) != 0 )
            {
                if ( req->blocks != 0 )
                    myfree(req->blocks,sizeof(*req->blocks) * req->n);
                myfree(req,req->allocsize);
            }
        }
        else if ( req->type == 'S' ) // blockhashes
        {
            if ( (req= iguana_recvblockhashes(coin,req,req->hashes,req->n)) != 0 )
            {
                myfree(req->hashes,sizeof(*req->hashes) * req->n);
                myfree(req,req->allocsize);
            }
        }
        else if ( req->type == 'U' ) // unconfirmed tx
        {
            if ( (req= iguana_recvunconfirmed(coin,req,req->serialized,req->n)) != 0 )
                myfree(req,req->allocsize);
        }
        else if ( req->type == 'T' ) // txids from inv
        {
            if ( (req= iguana_recvtxids(coin,req,req->hashes,req->n)) != 0 )
            {
                myfree(req->hashes,req->n * sizeof(*req->hashes));
                myfree(req,req->allocsize);
            }
        }
        else
        {
            printf("iguana_updatebundles unknown type.%c\n",req->type);
            myfree(req,req->allocsize);
        }
        flag++;
    }
    return(flag);
}

int32_t iguana_updatebundles(struct iguana_info *coin) // single threaded
{
    int32_t height,valid,newhwm=0,flag = 0; bits256 hash2; char hashstr[65]; struct iguana_block *block;
    flag = iguana_processbundlesQ(coin,&newhwm);
    while ( (block= iguana_blockptr(coin,coin->blocks.recvblocks)) != 0 && block->txdata != 0 )
        coin->blocks.recvblocks++;
    while ( (block= iguana_block(coin,coin->blocks.hashblocks)) != 0 && bits256_nonz(block->hash2) > 0 )
        coin->blocks.hashblocks++;
    while ( coin->blocks.issuedblocks < coin->blocks.recvblocks+coin->chain->bundlesize*coin->bundleswidth && coin->blocks.issuedblocks < coin->blocks.hashblocks )
    {
        iguana_queueblock(coin,coin->blocks.issuedblocks,iguana_blockhash(coin,&valid,coin->blocks.issuedblocks),0);
        coin->blocks.issuedblocks++;
    }
    if ( iguana_needhdrs(coin) > 0 )
    {
        if ( queue_size(&coin->hdrsQ) == 0 )
        {
            if ( coin->zcount++ > 100 )
            {
                height = (coin->blocks.hashblocks / coin->chain->bundlesize) * coin->chain->bundlesize;
                while ( height < (coin->longestchain - coin->chain->bundlesize) )
                {
                    if ( iguana_bundleready(coin,height) <= 0 )
                    {
                        if ( (block= iguana_block(coin,height)) != 0 && bits256_nonz(block->hash2) > 0 )
                        {
                            flag++;
                            printf("REQ HDR.(%s) %d\n",bits256_str(block->hash2),height);
                            init_hexbytes_noT(hashstr,block->hash2.bytes,sizeof(block->hash2));
                            queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(hashstr),1);
                        }
                    }
                    height += coin->chain->bundlesize;
                    coin->zcount = 0;
                }
            }
        } else coin->zcount = 0;
    }
    if ( queue_size(&coin->priorityQ) == 0 )
    {
        coin->pcount++;
        if ( (coin->bcount > 1 || time(NULL) > coin->recvtime) && iguana_blockptr(coin,coin->blocks.recvblocks) == 0 && coin->blocks.recvblocks < coin->blocks.hashblocks )
        {
            hash2 = iguana_blockhash(coin,&valid,coin->blocks.recvblocks);
            flag += (iguana_queueblock(coin,coin->blocks.recvblocks,hash2,1) > 0);
            coin->recvtime = (uint32_t)time(NULL);
        }
    } else coin->pcount = 0;
    if ( queue_size(&coin->blocksQ) == 0 )
    {
        coin->bcount++;
        if ( coin->bcount > 10 || time(NULL) > coin->recvtime+3 )
        {
            for (height=coin->blocks.recvblocks+1; height<coin->blocks.issuedblocks; height++)
            {
                if ( iguana_blockptr(coin,coin->blocks.recvblocks) == 0 )
                {
                    if ( (height % 100) == 0 )
                        printf("RETRY BLOCK.%d\n",height);
                    flag += (iguana_queueblock(coin,height,iguana_blockhash(coin,&valid,height),0) > 0);
                }
            }
            coin->recvtime = (uint32_t)time(NULL);
        }
    } else coin->bcount = 0;
    //if ( newhwm != 0 )
    //    flag += iguana_lookahead(coin,&hash2,coin->blocks.hwmheight);
    return(flag);
}

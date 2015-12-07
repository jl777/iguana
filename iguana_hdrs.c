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
    if ( coin->longestchain == 0 || coin->blocks.hwmheight < coin->longestchain-500 )
        return(1);
    else return(0);
}

void **iguana_recvblockptr(struct iguana_info *coin,int32_t height)
{
    int32_t checkpointi,i;
    if ( height <= 0 || height > coin->R.numwaitingbits )
        return(0);
    height--;
    i = (height % coin->chain->bundlesize);
    checkpointi = (height / coin->chain->bundlesize);
    return(&coin->R.checkpoints[checkpointi].txdata[i]);
}

void *iguana_recvblock(struct iguana_info *coin,int32_t height)
{
    void **ptrp;
    if ( height == 0 )
        return(coin->chain->genesis_hashdata);
    if ( (ptrp= iguana_recvblockptr(coin,height)) != 0 )
        return(*ptrp);
    else return(0);
}

int32_t iguana_avail(struct iguana_info *coin,int32_t height,int32_t n)
{
    int32_t i,nonz = 0;
    for (i=0; i<n; i++)
        if ( iguana_recvblock(coin,height+i) != 0 )
            nonz++;
    return(nonz);
}

struct iguana_checkpoint *iguana_checkpointheight(struct iguana_info *coin,int32_t *heightp,bits256 hash2,bits256 prev_block,int32_t deleteflag)
{
    int32_t i,j,miscompare = 0; struct iguana_checkpoint *checkpoint;
    *heightp = -1;
    for (i=0; i<coin->R.numcheckpoints; i++)
    {
        if ( i*coin->chain->bundlesize > coin->longestchain )
        {
            // printf("i.%d %d < longestchain.%d\n",i,i*coin->chain->bundlesize,coin->longestchain);
            break;
        }
        checkpoint = &coin->R.checkpoints[i];
        if ( checkpoint->height >= 0 && checkpoint->blocks != 0 )
        {
            if ( checkpoint->recvstart == 0 )
                continue;
            // printf("checkpointi.%d recvstart.%u finish.%u\n",i,checkpoint->recvstart,checkpoint->recvfinish);
            if ( memcmp(checkpoint->prevhash2.bytes,prev_block.bytes,sizeof(prev_block)) == 0 )
            {
                *heightp = checkpoint->height + 1;
                return(checkpoint);
            }
            for (j=0; j<checkpoint->num; j++)
            {
                if ( memcmp(checkpoint->blocks[j].hash2.bytes,hash2.bytes,sizeof(hash2)) == 0 )
                {
                    *heightp = checkpoint->height + 1 + j;
                    //printf("height.%d j.%d (%s) vs (%s) checkpoint.%d\n",*heightp,j,bits256_str(checkpoint->blocks[j].hash2),bits256_str2(hash2),checkpoint->height);
                    return(checkpoint);
                } else miscompare++;//, printf("%x ",(uint32_t)checkpoint->blocks[j].hash2.uints[7]);
            }
        } //else printf("skip checkpoint.%d %p\n",checkpoint->height,checkpoint->blocks);
    }
    printf("cant find.(%s) miscompares.%d %x\n",bits256_str(hash2),miscompare,(uint32_t)hash2.uints[7]);
    return(0);
}

void iguana_addcheckpoint(struct iguana_info *coin,int32_t height,bits256 hash2)
{
    int32_t checkpointi; struct iguana_checkpoint *checkpoint;
    if ( (checkpointi= (height / coin->chain->bundlesize)) >= coin->R.numcheckpoints || checkpointi < 0 )
        return;
    checkpoint = &coin->R.checkpoints[checkpointi];
    if ( checkpoint->num != 0 && memcmp(hash2.bytes,checkpoint->prevhash2.bytes,sizeof(hash2)) != 0 )
        printf("WARNING: overwriting checkpoint.%d\n",height);
    portable_mutex_init(&checkpoint->mutex);
    checkpoint->prevhash2 = hash2;
    checkpoint->checkpointi = checkpointi;
    checkpoint->hasheaders = coin->chain->hasheaders;
    checkpoint->num = coin->chain->bundlesize;
    checkpoint->height = (checkpointi * coin->chain->bundlesize);
    checkpoint->starttime = (uint32_t)time(NULL);
    printf("created checkpoint.%d: %s\n",height,bits256_str(hash2));
}

struct iguana_checkpoint *iguana_checkpoint(struct iguana_info *coin,bits256 prevhash2)
{
    int32_t checkpointi;
    for (checkpointi=0; checkpointi<coin->R.numcheckpoints; checkpointi++)
        if ( memcmp(&coin->R.checkpoints[checkpointi].prevhash2,&prevhash2,sizeof(prevhash2)) == 0 )
            return(&coin->R.checkpoints[checkpointi]);
    return(0);
}

int32_t iguana_savehdrs(struct iguana_info *coin)
{
    int32_t height,retval = 0; char fname[512],line[512]; bits256 hash2; FILE *fp;
    sprintf(fname,"%s_%s.txt",coin->symbol,"hdrs");
    if ( (fp= fopen(fname,"r")) != 0 )
    {
        if ( fgets(line,sizeof(line),fp) > 0 )
        {
            line[strlen(line)-1] = 0;
            if ( atoi(line) > coin->blocks.hwmheight )
            {
                //printf("skip save since %s has %d\n",fname,atoi(line));
                fclose(fp);
                return(0);
            }
        }
        fclose(fp);
    }
    if ( (fp= fopen(fname,"w")) != 0 )
    {
        fprintf(fp,"%d\n",coin->blocks.hwmheight);
        for (height=0; height<coin->blocks.hwmheight; height+=coin->chain->bundlesize)
        {
            hash2 = iguana_blockhash(coin,height);
            if ( memcmp(hash2.bytes,bits256_zero.bytes,sizeof(hash2)) != 0 )
            {
                fprintf(fp,"%d %s\n",height,bits256_str(hash2));
                retval = height;
            }
        }
        fclose(fp);
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
                    //printf("add checkpoint.%d (%s)\n",height,bits256_str(hash2));
                    iguana_addcheckpoint(coin,height,hash2);
                    queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(checkstr),1);
                }
            }
        }
    }
}

int32_t iguana_setwaitstart(struct iguana_info *coin,int32_t height)
{
    if ( coin->R.waitstart[height] == 0 )
        coin->R.numwaiting++;
    coin->R.waitstart[height] = (uint32_t)time(NULL);
    SETBIT(coin->R.waitingbits,height);
    return(coin->R.numwaiting);
}

int32_t iguana_queueblock(struct iguana_info *coin,int32_t height,bits256 hash2,int32_t priority)
{
    queue_t *Q; char *str; struct iguana_blockreq *req;
    if ( memcmp(hash2.bytes,bits256_zero.bytes,sizeof(hash2)) == 0 )
    {
        printf("null hash2?? height.%d\n",height);
        //getchar();
        return(0);
    }
    if ( height < 0 || (height >= coin->blocks.recvblocks && iguana_recvblock(coin,height) == 0) )
    {
        if ( priority != 0 )
            str = "priorityQ", Q = &coin->priorityQ;
        else if ( GETBIT(coin->R.waitingbits,height) == 0 )
            str = "blocksQ", Q = &coin->blocksQ;
        else str = "already pending", Q = 0;
        if ( Q != 0 )
        {
            req = mycalloc('r',1,sizeof(*req));
            req->hash2 = hash2;
            req->height = height;
            if ( 1 && (height % 100) == 0 )
                printf("%s height.%d %s recv.%d maxpeer.%d\n",str,height,bits256_str(hash2),coin->blocks.recvblocks,coin->MAXPEERS);
            if ( height >= 0 )
                req->checkpointi = (height / coin->chain->bundlesize);
            else req->checkpointi = -1;
            queue_enqueue(str,Q,&req->DL,0);
        }
        return(1);
    } else printf("iguana_queueblock skip.%d %s recvblocks.%d %p GETBIT.%d\n",height,bits256_str(hash2),coin->blocks.recvblocks,iguana_recvblock(coin,height),GETBIT(coin->R.waitingbits,height));
    return(0);
}

void iguana_queuebundle(struct iguana_info *coin,struct iguana_checkpoint *checkpoint)
{
    int32_t i;
    printf("queue bundle.%p %s height.%d num.%d waitingbits.%d\n",checkpoint,bits256_str(checkpoint->prevhash2),checkpoint->height,checkpoint->num,coin->R.numwaitingbits);
    for (i=0; i<checkpoint->num; i++)
    {
        //printf("bundle[i.%d] %d %s\n",i,checkpoint->height + 1 + i,bits256_str(checkpoint->blocks[i].hash2));
        if ( iguana_recvblock(coin,checkpoint->height + 1 + i) == 0 )
        {
            coin->R.blockhashes[checkpoint->height + 1 + i] = checkpoint->blocks[i].hash2;
            //iguana_queueblock(coin,checkpoint->height + 1 + i,checkpoint->blocks[i].hash2,0);
        }
    }
}

int32_t iguana_pollQs(struct iguana_info *coin,struct iguana_peer *addr)
{
    uint8_t serialized[sizeof(struct iguana_msghdr) + sizeof(uint32_t)*32 + sizeof(bits256)];
    char *hashstr=0,hexstr[65]; bits256 hash2; int32_t threshold,height=-1,datalen,flag = 0;
    struct iguana_blockreq *req=0; struct iguana_checkpoint *checkpoint;
    if ( iguana_needhdrs(coin) != 0 && addr->pendhdrs == 0 && (hashstr= queue_dequeue(&coin->hdrsQ,1)) != 0 )
    {
        if ( (datalen= iguana_gethdrs(coin,serialized,coin->chain->gethdrsmsg,hashstr)) > 0 )
        {
            //printf("%s request hdr.(%s) pend.%d\n",addr->ipaddr,hashstr,addr->pendhdrs);
            iguana_send(coin,addr,serialized,datalen,&addr->sleeptime);
            addr->pendhdrs++;
            flag++;
        } else printf("datalen.%d from gethdrs\n",datalen);
        free_queueitem(hashstr);
        hashstr = 0;
    }
    else
    {
        if ( (req= queue_dequeue(&coin->priorityQ,0)) != 0 )
        {
            threshold = coin->blocks.recvblocks + coin->chain->bundlesize;
            hash2 = req->hash2;
            checkpoint = iguana_checkpointheight(coin,&height,hash2,bits256_zero,0);
            //printf("dequeued priorityQ.(%s) height.%d vs %d width %d/%d %p\n",bits256_str(hash2),req->height,height,coin->widthready,coin->width,checkpoint);
        }
        else if ( (req= queue_dequeue(&coin->blocksQ,0)) != 0 )
        {
            threshold = coin->blocks.recvblocks + 100*coin->chain->bundlesize;
            hash2 = req->hash2;
            checkpoint = iguana_checkpointheight(coin,&height,hash2,bits256_zero,0);
            if ( height != req->height || checkpoint == 0 )
            {
                printf("blocksQ ht.%d vs %d dequeued.(%s) for %s checkpoint.%p\n",req->height,height,bits256_str(hash2),addr->ipaddr,checkpoint);
                //myfree(req,sizeof(*req));
                //getchar();
                //return(0);
            }
        }
        else threshold = 0;
    }
    if ( req != 0 )
    {
        if ( height >= 0 && height > threshold )
        {
            //printf("height.%d > threshold.%d\n",height,threshold);
            queue_enqueue("resubmit",&coin->blocksQ,&req->DL,0);
        }
        else
        {
            init_hexbytes_noT(hexstr,hash2.bytes,sizeof(hash2));
            if ( memcmp(hash2.bytes,bits256_zero.bytes,sizeof(hash2)) == 0 )
            {
                printf("zero hash?? %s\n",hexstr);
                myfree(req,sizeof(*req));
                //getchar();
            }
            else if ( (datalen= iguana_getdata(coin,serialized,MSG_BLOCK,hexstr)) > 0 )
            {
                // printf("%s send block request %s %.0f\n",addr->ipaddr,hexstr,milliseconds());
                iguana_send(coin,addr,serialized,datalen,&addr->sleeptime);
                if ( height >= 0 )
                    iguana_setwaitstart(coin,height);
                addr->pendblocks++;
                addr->pendtime = (uint32_t)time(NULL);
                flag++;
                if ( req->blockhashes != 0 )
                    queue_enqueue("pendingQ",&addr->pendingQ,&req->DL,0);
                else myfree(req,sizeof(*req));//queue_enqueue("pendblocksQ",&addr->pendblocksQ[0],&req->DL,0);
            }
        }
    }
    return(flag);
}

int32_t iguana_waitstart(struct iguana_info *coin,int32_t height,bits256 hash2,int32_t priority)
{
    if ( height < 0 || iguana_recvblock(coin,height) == 0 )
        return(iguana_queueblock(coin,height,hash2,priority));
    else if ( height < coin->R.numwaitingbits )
        printf("iguana_waitstart ignore height.%d < %d, %p GETBIT.%d\n",height,coin->R.numwaitingbits,iguana_recvblock(coin,height),GETBIT(coin->R.waitingbits,height));
    return(0);
}

int32_t iguana_waitclear(struct iguana_info *coin,int32_t height)
{
    if ( height < coin->R.numwaitingbits )
    {
        //printf("%d waitclear.%d parsed.%d\n",coin->R.numwaiting,height,coin->blocks.recvblocks);
        if ( coin->R.numwaiting > 0 )
            coin->R.numwaiting--;
        coin->R.waitstart[height] = 0;
        CLEARBIT(coin->R.waitingbits,height);
        return(0);
    }
    return(-1);
}

void iguana_gotblockhashesM(struct iguana_info *coin,struct iguana_peer *addr,bits256 *blockhashes,int32_t n)
{
    static bits256 lasthash2;
    struct iguana_blockreq *req; int32_t height;
    addr->lastrequest = bits256_zero;
    addr->recvhdrs++;
    if ( addr->pendhdrs > 0 )
        addr->pendhdrs--;
    coin->R.lasthdrtime = (uint32_t)time(NULL);
    if ( memcmp(lasthash2.bytes,blockhashes[0].bytes,sizeof(lasthash2)) != 0 )
    {
        if ( n <= 2 )
        {
            printf("gotblockhashes[%d] %s pend.%d\n",n,bits256_str(blockhashes[0]),addr->pendhdrs);
            lasthash2 = blockhashes[0];
        }
    }
    if ( n > 2 )
    {
        if ( n > coin->chain->bundlesize )
            printf("warning: %s gotheaders.%d is too many vs. %d\n",coin->symbol,n,coin->chain->bundlesize);
        req = mycalloc('r',1,sizeof(*req));
        req->hash2 = blockhashes[0];
        req->blockhashes = blockhashes;
        req->n = n;
        iguana_checkpointheight(coin,&height,blockhashes[0],bits256_zero,0);
        if ( req->height >= 0 )
        {
            req->checkpointi = (req->height / coin->chain->bundlesize);
            //printf("blocksQ.%s height.%d\n",bits256_str(blockhashes[0]),height);
            //queue_enqueue("blocksQ",&coin->blocksQ,&req->DL,0);
        }
        else
        {
            req->checkpointi = -1;
            //printf("priorityQ.%s height.%d\n",bits256_str(blockhashes[0]),height);
           //queue_enqueue("priorityQ",&coin->priorityQ,&req->DL,0);
        }
        printf("blocksQ.%s height.%d req->height.%d\n",bits256_str(blockhashes[0]),height,req->height);
        queue_enqueue("blocksQ",&coin->blocksQ,&req->DL,0);
    } else myfree(blockhashes,n * sizeof(*blockhashes));
}

void iguana_gotblockM(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_block *block,struct iguana_msgtx *txarray,int32_t numtx,uint8_t *data,int32_t datalen)
{
    int32_t h,i,height; char hashstr[65]; uint32_t now; bits256 prevhash2;
    struct iguana_blockreq *req; struct iguana_checkpoint *checkpoint;
    iguana_gotdata(coin,addr,block->height,block->hash2);
    now = (uint32_t)time(NULL);
    checkpoint = iguana_checkpointheight(coin,&height,block->hash2,block->prev_block,1);
    //printf("%s got block.%d height.%d\n",addr!=0?addr->ipaddr:"local",block->height,height);
    if ( addr != 0 )
    {
        if ( addr->pendblocks > 0 )
            addr->pendblocks--;
        addr->lastblockrecv = now;
        addr->recvblocks += 1.;
        addr->recvtotal += datalen;
        if ( (req= queue_dequeue(&addr->pendingQ,0)) != 0 ) // should only have depth 1!
        {
            if ( memcmp(req->hash2.bytes,block->hash2.bytes,sizeof(req->hash2)) == 0 )
            {
                if ( req->blockhashes != 0 )
                {
                    iguana_gotdata(coin,addr,block->height,block->hash2);
                    iguana_addcheckpoint(coin,block->height-1,block->prev_block);
                    if ( (checkpoint= iguana_checkpoint(coin,block->prev_block)) != 0 )
                    {
                        portable_mutex_lock(&checkpoint->mutex);
                        if ( checkpoint->blocks == 0 )
                        {
                            checkpoint->blockhashes = req->blockhashes;
                            checkpoint->num = req->n;
                            checkpoint->checkpointi = (block->height / coin->chain->bundlesize);
                            checkpoint->firsthash2 = block->hash2;
                            checkpoint->lasthash2 = req->blockhashes[req->n-1];
                            checkpoint->height = block->height - 1;
                            checkpoint->blocks = mycalloc('B',req->n,sizeof(*checkpoint->blocks));
                            checkpoint->blocks[0] = *block;
                            prevhash2 = block->prev_block;
                            for (i=0; i<req->n; i++)
                            {
                                checkpoint->blocks[i].prev_block = prevhash2;
                                checkpoint->blocks[i].hash2 = req->blockhashes[i];
                                prevhash2 = req->blockhashes[i];
                                height = (checkpoint->height + 1 + i);
                                if ( (height % coin->chain->bundlesize) == 0 )
                                {
                                    if ( coin->R.checkpoints[height / coin->chain->bundlesize].num == 0 )
                                    {
                                        init_hexbytes_noT(hashstr,req->blockhashes[i].bytes,sizeof(req->blockhashes[i]));
                                        iguana_addcheckpoint(coin,height,req->blockhashes[i]);
                                        queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(hashstr),1);
                                    }
                                }
                            }
                            printf("initialized checkpointi.%d %d\n",checkpoint->checkpointi,checkpoint->height);
                        }
                        portable_mutex_unlock(&checkpoint->mutex);
                    } else printf("couldnt find matching checkpoint for %s\n",bits256_str(block->prev_block));
                    myfree(req->blockhashes,req->n * sizeof(*req->blockhashes));
                    myfree(req,sizeof(*req));
                } else printf("unexpected missing blockhashes.%p\n",req->blockhashes);
            } else printf("unexpected hash2 mismatch with height.%d\n",block->height);
        }
        else
        {
            if ( checkpoint == 0 )
            {
                printf("cant find checkpoint.(%s)\n",bits256_str(block->hash2));
                return;
            }
            if ( height > checkpoint->height && height <= checkpoint->height+checkpoint->num )
            {
                h = height - checkpoint->height - 1;
                portable_mutex_lock(&checkpoint->mutex);
                if ( checkpoint->numvalid < checkpoint->num && checkpoint->txdata[h] == 0 )
                {
                    checkpoint->blocks[h] = *block;
                    if ( iguana_recvblockptr(coin,height) == &checkpoint->txdata[h] )
                    {
                        checkpoint->txdata[h] = txarray, checkpoint->numtxs[h] = numtx;
                        printf("GOT.%d | received.%d\n",height,coin->blocks.recvblocks);
                        txarray = 0;
                        if ( ++checkpoint->numvalid == checkpoint->num )
                        {
                            checkpoint->recvfinish = now;
                            checkpoint->lastduration = (checkpoint->recvfinish - checkpoint->recvstart);
                            dxblend(&coin->R.avetime,checkpoint->lastduration,.9);
                            /*if ( checkpoint->lastduration < coin->R.avetime )
                                coin->R.faster++;
                            else coin->R.slower++;
                            if ( coin->R.faster > 3*coin->R.slower || coin->R.slower > 3*coin->R.faster )
                            {
                                dir = (coin->R.maxrecvbundles - coin->R.prevmaxrecvbundles);
                                if ( coin->R.slower >= coin->R.faster )
                                    dir = -dir;
                                if ( dir > 0 )
                                    dir = 1;
                                else if ( coin->R.maxrecvbundles > 2 )
                                    dir = -1;
                                else dir = 0;
                                printf("(%d vs %f) faster.%d slower.%d -> dir.%d apply -> %d\n",checkpoint->lastduration,coin->R.avetime,coin->R.faster,coin->R.slower,dir,coin->R.maxrecvbundles + dir);
                                coin->R.prevmaxrecvbundles = coin->R.maxrecvbundles;
                                coin->R.maxrecvbundles += dir;
                                coin->R.slower = coin->R.faster = 0;
                            }*/
                            coin->R.finishedbundles++;
                            printf("submit emit.%d height.%d\n",checkpoint->checkpointi,checkpoint->height);
                            queue_enqueue("emitQ",&coin->emitQ,&checkpoint->DL,0);
                        }
                        else
                        {
                            if ( coin->R.waitstart[height] > 0 )
                            {
                                if ( checkpoint->firstblocktime == 0 )
                                    checkpoint->firstblocktime = now;
                                checkpoint->durationsum += (now - coin->R.waitstart[height] + 1);
                                checkpoint->aveduration = (checkpoint->durationsum / checkpoint->numvalid);
                            }
                        }
                    } else printf("recvblockptr error? height.%d %p %p h.%d\n",height,iguana_recvblockptr(coin,height),&checkpoint->txdata[h],h);
                } else if ( (rand() % 1000) == 0 )
                    printf("interloper! already have txs[%d] for checkpointi.%d\n",h,checkpoint!=0?checkpoint->height:-1);
                portable_mutex_unlock(&checkpoint->mutex);
            } else printf("height.%d outside range of checkpointi.%d %d\n",height,checkpoint!=0?checkpoint->height:-1,checkpoint!=0?checkpoint->height:-1);
        }
        //iguana_waitclear(coin,block->height);
        if ( 1 && (rand() % 1000) == 0 )
            printf("%-15s pend.(%d %d) got block.%-6d recvblocks %-8.0f recvtotal %-10.0f\n",addr->ipaddr,addr->pendhdrs,addr->pendblocks,block->height,addr->recvblocks,addr->recvtotal);
    }
    if ( txarray != 0 )
        iguana_freetx(txarray,numtx);
    myfree(block,sizeof(*block));
}

void iguana_gotheadersM(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_block *blocks,int32_t n)
{
    struct iguana_checkpoint *checkpoint; int32_t i; char hexstr[65];
    addr->lastrequest = bits256_zero;
    addr->recvhdrs++;
    if ( addr->pendhdrs > 0 )
        addr->pendhdrs--;
    //printf("%s blocks[0] %d gotheaders pend.%d %.0f\n",addr->ipaddr,blocks[0].height,addr->pendhdrs,milliseconds());
    coin->R.lasthdrtime = (uint32_t)time(NULL);
    if ( (checkpoint= iguana_checkpoint(coin,blocks[0].prev_block)) != 0 )
    {
        if ( n > coin->chain->bundlesize )
            printf("warning: %s gotheaders.%d is too many vs. %d\n",coin->symbol,n,coin->chain->bundlesize);
        portable_mutex_lock(&checkpoint->mutex);
        if ( checkpoint->blocks == 0 )
        {
            checkpoint->num = n;
            checkpoint->blocks = blocks;
            checkpoint->firsthash2 = blocks[0].hash2;
            checkpoint->lasthash2 = blocks[n-1].hash2;
            for (i=0; i<n; i++)
            {
                blocks[i].height = (checkpoint->height + i + 1);
                iguana_gotdata(coin,addr,checkpoint->height+i+1,blocks[i].hash2);
                if ( (blocks[i].height % coin->chain->bundlesize) == 0 )
                {
                    if ( coin->R.checkpoints[blocks[i].height / coin->chain->bundlesize].num == 0 )
                    {
                        init_hexbytes_noT(hexstr,blocks[i].hash2.bytes,sizeof(blocks[i].hash2));
                        queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(hexstr),1);
                    }
                }
            }
            printf("%s set checkpoint.%d %s\n",addr->ipaddr,checkpoint->height,bits256_str(blocks[0].prev_block));
        }
        portable_mutex_unlock(&checkpoint->mutex);
    } else printf("ERROR iguana_gotheaders got checkpoint.(%s) n.%d that cant be found?\n",bits256_str(blocks[0].prev_block),n);
}

int32_t iguana_maptxdata(struct iguana_info *coin,struct iguana_checkpoint *checkpoint)
{
    void *fileptr; int32_t i,height; uint32_t *offsets;
    if ( (fileptr= iguana_mappedptr(0,&checkpoint->M,0,0,checkpoint->fname)) != 0 )
    {
        offsets = fileptr;
        for (i=0; i<checkpoint->num; i++)
        {
            height = checkpoint->height + 1 + i;
            if ( iguana_recvblockptr(coin,height) == &checkpoint->txdata[i] )
                checkpoint->txdata[i] = (void *)((long)fileptr + offsets[i]);
            else printf("iguana_recvblockptr(coin,%d) %p != %p &checkpoint->txdata[%d]\n",height,iguana_recvblockptr(coin,height),&checkpoint->txdata[i],i);
        }
        return(checkpoint->num);
    }
    printf("error mapping (%s)\n",checkpoint->fname);
    return(-1);
}

void iguana_emittxdata(struct iguana_info *coin,struct iguana_checkpoint *checkpoint)
{
    FILE *fp; int32_t i,numtx; uint32_t offsets[_IGUANA_HDRSCOUNT+1]; long len; struct iguana_msgtx *txarray;
    checkpoint->emitstart = (uint32_t)time(NULL);
    sprintf(checkpoint->fname,"tmp/%s/txdata.%d",coin->symbol,checkpoint->height);
    if ( (fp= fopen(checkpoint->fname,"wb")) != 0 )
    {
        memset(offsets,0,sizeof(offsets));
        if ( (len= fwrite(offsets,sizeof(*offsets),checkpoint->num+1,fp)) != checkpoint->num+1 )
            printf("%s: error writing blank offsets len.%ld != %d\n",checkpoint->fname,len,checkpoint->num+1);
        for (i=0; i<checkpoint->num; i++)
        {
            offsets[i] = (uint32_t)ftell(fp);
            if ( iguana_recvblockptr(coin,checkpoint->height + 1 + i) == &checkpoint->txdata[i] )
            {
                if ( (txarray= checkpoint->txdata[i]) != 0 && (numtx= checkpoint->numtxs[i]) > 0 )
                {
                    iguana_emittxarray(coin,checkpoint,&checkpoint->blocks[i],txarray,numtx);
                    iguana_freetx(txarray,numtx);
                }
            } else printf("emittxdata: error with recvblockptr[%d]\n",checkpoint->height + 1 + i);
        }
        offsets[i] = (uint32_t)ftell(fp);
        rewind(fp);
        if ( (len= fwrite(offsets,sizeof(*offsets),checkpoint->num+1,fp)) != checkpoint->num+1 )
            printf("%s: error writing offsets len.%ld != %d\n",checkpoint->fname,len,checkpoint->num+1);
        fclose(fp), fp = 0;
        //iguana_maptxdata(coin,checkpoint);
        if ( checkpoint->blocks != 0 )
            myfree(checkpoint->blocks,checkpoint->num * sizeof(*checkpoint->blocks));
        checkpoint->blocks = 0;
    }
    checkpoint->emitfinish = (uint32_t)time(NULL);
}

int32_t iguana_updatewaiting(struct iguana_info *coin,int32_t starti,int32_t max)
{
    int32_t i,height,gap,n = 0; uint32_t now;
    now = (uint32_t)time(NULL);
    height = starti;
    for (i=0; i<max; i++,height++)
    {
        gap = (height - coin->blocks.recvblocks);
        if ( gap >= 0 )
            gap = sqrt(gap);
        if ( gap < 13 )
            gap = 13;
        if ( height < coin->R.numwaitingbits && iguana_recvblock(coin,height) == 0 && now > (coin->R.waitstart[height] + gap) && memcmp(bits256_zero.bytes,coin->R.blockhashes[height].bytes,sizeof(bits256)) != 0 )
        {
            //printf("restart height.%d width.%d widthready.%d %s\n",height,coin->width,coin->widthready,bits256_str(coin->R.blockhashes[height]));
            iguana_waitclear(coin,height);
            iguana_waitstart(coin,height,coin->R.blockhashes[height],0);
        } //else printf("%d %d %p %u\n",height,coin->R.numwaitingbits,coin->R.recvblocks[height],coin->R.waitstart[height]);
    }
    //printf("height.%d max.%d\n",starti,max);
    height = starti;
    for (i=0; i<max; i++,height++)
        if ( iguana_recvblock(coin,height) != 0 )
            n++;
    return(n);
}

int32_t iguana_updatehdrs(struct iguana_info *coin)
{
    int32_t i,j,m,height,run,duration,flag = 0; uint32_t now; struct iguana_checkpoint *checkpoint;
    if ( iguana_needhdrs(coin) == 0 )
        return(flag);
    now = (uint32_t)time(NULL);
    run = -1;
    for (i=0; i<coin->R.numcheckpoints; i++)
    {
        if ( i*coin->chain->bundlesize > coin->longestchain )
            break;
        checkpoint = &coin->R.checkpoints[i];
        if ( checkpoint->blocks != 0 )
        {
            if ( checkpoint->recvstart == 0 )
            {
                if ( (coin->R.startedbundles - coin->R.finishedbundles) < coin->R.maxrecvbundles )
                {
                    iguana_queuebundle(coin,checkpoint);
                    checkpoint->recvstart = now;
                    coin->R.startedbundles++;
                    printf("startbundle.%d (%d - %d)\n",checkpoint->height,coin->R.startedbundles,coin->R.finishedbundles);
                    flag++;
                }
            }
            else if ( checkpoint->recvfinish == 0 )
            {
                for (j=m=0; j<checkpoint->num; j++)
                {
                    height = checkpoint->height+j+1;
                    if ( iguana_recvblock(coin,height) != 0 )
                        m++;
                    /*else if ( coin->R.waitstart[height] > 0 )
                    {
                        duration = (now - coin->R.waitstart[height]);
                        if ( duration > 60 || (duration > 10 && checkpoint->numvalid > 13 && duration > 3.*checkpoint->aveduration) )
                        {
                            if ( now > checkpoint->lastdisp+15 )
                                printf("height.%d in checkpoint.%d duration.%d vs ave %.3f\n",height,checkpoint->height,duration,checkpoint->aveduration);
                            iguana_waitclear(coin,height);
                            iguana_waitstart(coin,height,checkpoint->blocks[j].hash2,1);
                        }
                    }
                    else if ( checkpoint->firstblocktime > 0 && (now - checkpoint->firstblocktime) > 60 )
                    {
                        if ( now > checkpoint->lastdisp+15 )
                            printf("height.%d in checkpoint.%d ave %.3f\n",height,checkpoint->height,checkpoint->aveduration);
                        iguana_waitclear(coin,height);
                        iguana_waitstart(coin,height,checkpoint->blocks[j].hash2,1);
                        checkpoint->firstblocktime = now;
                    }*/
                }
                if ( now > checkpoint->lastdisp+15 )
                {
                    printf("bundle.%d (%d %d) elapsed.%d (%d - %d) %d | %.2f minutes\n",checkpoint->checkpointi,checkpoint->height,m,(int32_t)(now - checkpoint->recvstart),coin->R.startedbundles,coin->R.finishedbundles,coin->R.maxrecvbundles,(double)(now - coin->starttime)/60.);
                    checkpoint->lastdisp = now;
                }
            }
            else if ( run == i-1 )
                run++;
        }
    }
    //iguana_lookahead(coin,&hash2,0);
    return(flag);
}


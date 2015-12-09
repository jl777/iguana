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

int32_t iguana_bundlei(struct iguana_info *coin,int32_t *blockip,int32_t height)
{
    int32_t bundlei;
    *blockip = -1;
    if ( height <= 0 || height > coin->R.numwaitingbits )
        return(-1);
    height--;
    *blockip = (height % coin->chain->bundlesize);
    if ( (bundlei= (height / coin->chain->bundlesize)) < IGUANA_MAXBUNDLES )
        return(bundlei);
    else return(-1);
}

void **iguana_recvblockptr(struct iguana_info *coin,int32_t *blockip,int32_t height)
{
    int32_t bundlei; struct iguana_bundle *bp;
    if ( (bundlei= iguana_bundlei(coin,blockip,height)) >= 0 )
    {
        if ( (bp= coin->B[bundlei]) != 0 )
            return(&bp->txdata[*blockip]);
    }
    return(0);
}

void *iguana_recvblock(struct iguana_info *coin,int32_t height)
{
    void **ptrp; int32_t blocki;
    if ( height == 0 )
        return(coin->chain->genesis_hashdata);
    if ( (ptrp= iguana_recvblockptr(coin,&blocki,height)) != 0 )
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

struct iguana_bundle *iguana_bundleinit(struct iguana_info *coin,int32_t height,bits256 hash2)
{
    int32_t bundlei,blocki; struct iguana_bundle *bp = 0;
    if ( height < 0 || (height % coin->chain->bundlesize) != 0 )
    {
        printf("bundleinit error: height.%d %s\n",height,bits256_str(hash2));
        return(bp);
    }
    portable_mutex_lock(&coin->bundles_mutex);
    if ( (bundlei= iguana_bundlei(coin,&blocki,height+1)) >= 0 )
    {
        if ( (bp= coin->B[bundlei]) != 0 )
        {
            if ( memcmp(hash2.bytes,bp->prevhash2.bytes,sizeof(hash2)) != 0 )
            {
                if ( bits256_nonz(hash2) > 0 )
                {
                    if ( bits256_nonz(bp->prevhash2) > 0 )
                    {
                        printf("bundleinit[%d]: %d hash conflict have %s, got %s\n",bp->bundlei,bp->height,bits256_str(bp->prevhash2),bits256_str2(hash2));
                        //getchar();
                        portable_mutex_unlock(&coin->bundles_mutex);
                        return(0);
                    }
                    bp->prevhash2 = hash2;
                    iguana_blockhashset(coin,height,hash2,bp);
                    printf("bundleinit: set starting hash.(%s) for %d\n",bits256_str(hash2),bp->height);
                }
            }
        }
        else
        {
            bp = mycalloc('b',1,sizeof(*bp));
            coin->B[bundlei] = bp; // cant change values once set to nonzero
            bp->prevhash2 = hash2;
            bp->bundlei = bundlei;
            bp->hasheaders = coin->chain->hasheaders;
            bp->num = coin->chain->bundlesize;
            bp->height = (bundlei * coin->chain->bundlesize);
            bp->starttime = (uint32_t)time(NULL);
            if ( bits256_nonz(hash2) > 0 )
            {
                iguana_blockhashset(coin,height,hash2,0);
                printf("created bundle.%d: %s coin->B[%d] <- %p\n",height,bits256_str(hash2),bundlei,bp);
            }
        }
    }
    portable_mutex_unlock(&coin->bundles_mutex);
    return(bp);
}

struct iguana_bundle *iguana_bundlefindprev(struct iguana_info *coin,int32_t *heightp,bits256 prevhash2)
{
    struct iguana_block *block;
    *heightp = -1;
    if ( (block= iguana_blockfind(coin,prevhash2)) != 0 )
    {
        *heightp = block->hh.itemind;
        if ( block->bundle == 0 )
        {
            if ( *heightp == 0 )
                block->bundle = coin->B[0];
            else block->bundle = coin->B[(block->hh.itemind - 1) / coin->chain->bundlesize];
        }
        return(block->bundle);
    }
    else return(0);
}

int32_t iguana_bundleready(struct iguana_info *coin,int32_t height)
{
    int32_t i,num = coin->chain->bundlesize; struct iguana_bundle *bp;
    if ( (bp= coin->B[height / num]) != 0 && bp->havehashes == num )
        return(1);
    if ( bp != 0 )
        bp->havehashes = 0;
    for (i=0; i<num; i++)
        if ( iguana_havehash(coin,height+i) <= 0 )
        return(0);
    if ( bp != 0 )
        bp->havehashes = num;
    return(1);
}

int32_t iguana_bundleset(struct iguana_info *coin,int32_t origheight,bits256 hash2)
{
    int32_t bundlei,blocki,height = origheight; struct iguana_bundle *bp = 0;
    //printf("bundleset.(%d %s)\n",height,bits256_str(hash2));
    if ( (height % coin->chain->bundlesize) == 0 && height > 0 )
    {
        iguana_blockhashset(coin,origheight,hash2,0);
        return(0);
    }
    if ( (bundlei= iguana_bundlei(coin,&blocki,height)) >= 0 && bundlei >= 0 && (bp= coin->B[bundlei]) != 0 )
    {
        if ( height > bp->height && height < bp->height+bp->num )
        {
            if ( iguana_blockhashset(coin,origheight,hash2,bp) != 0 )
            {
                return(0);
            }
            printf("iguana_bundleset error setting bundle height.%d %s\n",height,bits256_str(hash2));
        } else printf("iguana_bundleset illegal height.%d for bundle.%d\n",height,bp->height);
    } else printf("iguana_bundleset illegal height.%d bundlei.%d blocki.%d bp.%p\n",height,bundlei,blocki,bp);
    return(-1);
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
                        if ( height > coin->R.numwaitingbits-coin->chain->bundlesize*10 )
                            iguana_recvalloc(coin,height + coin->chain->bundlesize*100);
                        iguana_bundleinit(coin,height,hash2);
                        if ( height <= coin->chain->bundlesize*coin->bundleswidth )
                            queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(checkstr),1);
                        queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(checkstr),1);
                    } else iguana_blockhashset(coin,height,hash2,0);
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
    if ( bits256_nonz(hash2) == 0 )
    {
        printf("cant queue zerohash height.%d\n",height), getchar();
        return(-1);
    }
    if ( height < 0 || (height >= coin->blocks.recvblocks && iguana_recvblock(coin,height) == 0) )
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
        if ( height >= 0 && (height < coin->blocks.recvblocks || iguana_recvblock(coin,height) != 0) )
        {
            printf("skip.%d vs recvblocks.%d %p\n",height,coin->blocks.recvblocks,iguana_recvblock(coin,height));
            myfree(req,sizeof(*req));
        }
        else
        {
            init_hexbytes_noT(hexstr,hash2.bytes,sizeof(hash2));
            if ( (datalen= iguana_getdata(coin,serialized,MSG_BLOCK,hexstr)) > 0 )
            {
                //printf("%s %s REQ BLOCK.%d\n",addr->ipaddr,hexstr,iguana_blockheight(coin,hash2));
                iguana_send(coin,addr,serialized,datalen,&addr->sleeptime);
                if ( height >= 0 )
                    iguana_setwaitstart(coin,height);
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
    char hashstr[65]; int32_t valid,h,flag = 0;
    if ( height >= 0 && bits256_nonz(hash2) > 0 )
    {
        //printf("gotdata.%d %s i.%d n.%d\n",height,bits256_str(hash2),i,n);
        if ( iguana_needhdrs(coin) > 0 )
            iguana_bundleset(coin,height,hash2);
        if ( (height % coin->chain->bundlesize) == 0 )
        {
            iguana_bundleinit(coin,height,hash2);
            if ( 0 && iguana_bundleready(coin,height) == 0 )
            {
                init_hexbytes_noT(hashstr,hash2.bytes,sizeof(hash2));
                queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(hashstr),1);
            }
            h = height - coin->chain->bundlesize;
            while ( iguana_bundleready(coin,h) > 0 )
            {
                h += coin->chain->bundlesize;
                coin->R.tophash2 = iguana_blockhash(coin,&valid,h);
                coin->R.topheight = h;
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

int32_t iguana_processbundlesQ(struct iguana_info *coin,int32_t *newhwmp) // single threaded
{
    int32_t i,j,n,numtx,height,blocki,newhwm=0,flag = 0; bits256 *blockhashes,*txids;
    struct iguana_bundle *bp; void **ptrp;
    struct iguana_bundlereq *req;  struct iguana_block *blocks,*block; struct iguana_msgtx *txarray,*tx;
    while ( (req= queue_dequeue(&coin->bundlesQ,0)) != 0 )
    {
        //printf("bundlesQ.%p type.%c n.%d\n",req,req->type,req->n);
        if ( req->type == 'B' ) // one block with all txdata
        {
            blocks = req->blocks, block = blocks, txarray = req->txarray, numtx = req->n;
            bp = iguana_bundlefindprev(coin,&height,block->prev_block);
            height++;
            //printf("%s got block.(%s) height.%d\n",req->addr!=0?req->addr->ipaddr:"local",bits256_str(block->hash2),height);
            if ( height > 0 )
            {
                if ( (ptrp= iguana_recvblockptr(coin,&blocki,height)) != 0 )
                {
                    (*ptrp) = (void *)txarray, bp->numtxs[blocki] = n; // txarray = 0;
                    //printf("ptrp.%p blocki.%d\n",ptrp,blocki);
                }
                else printf("cant get ptrp.%d\n",height), getchar();
                iguana_bundleset(coin,height,block->hash2);
                iguana_gotdata(coin,req->addr,height,block->hash2,0,0);
                if ( bp != 0 && iguana_bundleready(coin,height-1) <= 0 )
                {
                    printf("check for pendings.%d height.%d\n",coin->numpendings,height);
                    if ( height == coin->blocks.hwmheight )
                        newhwm++;
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
            }
            myfree(blocks,sizeof(*blocks));
            if ( txarray != 0 )
                iguana_freetx(txarray,numtx);
        }
        else if ( req->type == 'H' ) // blockhdrs (doesnt have txn_count!)
        {
            blocks = req->blocks;
            n = req->n;
            if ( iguana_bundlefindprev(coin,&height,blocks[0].prev_block) != 0 && height >= 0 )
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
                            newhwm++;
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
            myfree(blocks,sizeof(*blocks) * n);
        }
        else if ( req->type == 'S' ) // blockhashes
        {
            blockhashes = req->hashes;
            n = req->n;
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
            }
            if ( blockhashes != 0 )
            {
                //printf("cant find blockhashes[%d] %s\n",n,bits256_str(blockhashes[0])); // or RTblock
                myfree(blockhashes,sizeof(*blockhashes) * n);
            }
        }
        else if ( req->type == 'U' ) // unconfirmed tx
        {
            tx = req->txarray;
            iguana_freetx(tx,1);
        }
        else if ( req->type == 'T' ) // txids from inv
        {
            txids = req->hashes;
            n = req->n;
            myfree(txids,n * sizeof(*txids));
        }
        else printf("iguana_updatebundles unknown type.%c\n",req->type);
        flag++;
        if ( req != 0 )
            myfree(req,sizeof(*req));
    }
    (*newhwmp) = newhwm;
    return(flag);
}

int32_t iguana_maptxdata(struct iguana_info *coin,struct iguana_bundle *bundle)
{
    void *fileptr; int32_t i,height,blocki; uint32_t *offsets;
    if ( (fileptr= iguana_mappedptr(0,&bundle->M,0,0,bundle->fname)) != 0 )
    {
        offsets = fileptr;
        for (i=0; i<bundle->num; i++)
        {
            height = bundle->height + 1 + i;
            if ( iguana_recvblockptr(coin,&blocki,height) == &bundle->txdata[i] )
                bundle->txdata[i] = (void *)((long)fileptr + offsets[i]);
            else printf("iguana_recvblockptr(coin,%d) %p != %p &bundle->txdata[%d]\n",height,iguana_recvblockptr(coin,&blocki,height),&bundle->txdata[i],i);
        }
        return(bundle->num);
    }
    printf("error mapping (%s)\n",bundle->fname);
    return(-1);
}

void iguana_emittxdata(struct iguana_info *coin,struct iguana_bundle *bundle)
{
    FILE *fp; int32_t i,numtx,blocki; uint32_t offsets[_IGUANA_HDRSCOUNT+1]; long len; struct iguana_msgtx *txarray;
    bundle->emitstart = (uint32_t)time(NULL);
    sprintf(bundle->fname,"tmp/%s/txdata.%d",coin->symbol,bundle->height);
    if ( (fp= fopen(bundle->fname,"wb")) != 0 )
    {
        memset(offsets,0,sizeof(offsets));
        if ( (len= fwrite(offsets,sizeof(*offsets),bundle->num+1,fp)) != bundle->num+1 )
            printf("%s: error writing blank offsets len.%ld != %d\n",bundle->fname,len,bundle->num+1);
        for (i=0; i<bundle->num; i++)
        {
            offsets[i] = (uint32_t)ftell(fp);
            if ( iguana_recvblockptr(coin,&blocki,bundle->height + 1 + i) == &bundle->txdata[i] )
            {
                if ( (txarray= bundle->txdata[i]) != 0 && (numtx= bundle->numtxs[i]) > 0 )
                {
                    iguana_emittxarray(coin,fp,bundle,&bundle->blocks[i],txarray,numtx);
                    iguana_freetx(txarray,numtx);
                } else printf("emittxdata: unexpected missing txarray[%d]\n",i);
            } else printf("emittxdata: error with recvblockptr[%d]\n",bundle->height + 1 + i);
        }
        offsets[i] = (uint32_t)ftell(fp);
        rewind(fp);
        if ( (len= fwrite(offsets,sizeof(*offsets),bundle->num+1,fp)) != bundle->num+1 )
            printf("%s: error writing offsets len.%ld != %d\n",bundle->fname,len,bundle->num+1);
        fclose(fp), fp = 0;
        //iguana_maptxdata(coin,bundle);
        //if ( bundle->blocks != 0 )
        //    myfree(bundle->blocks,bundle->num * sizeof(*bundle->blocks));
        //bundle->blocks = 0;
    }
    bundle->emitfinish = (uint32_t)time(NULL);
}

/*
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

int32_t iguana_updatewaiting(struct iguana_info *coin,int32_t starti,int32_t max)
{
    int32_t i,height,gap,n = 0; uint32_t now;
    now = (uint32_t)time(NULL);
    height = starti;
    iguana_waitclear(coin,height);
    iguana_waitstart(coin,height,coin->R.blockhashes[height],1);
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

*/

int32_t iguana_updatebundles(struct iguana_info *coin) // single threaded
{
    int32_t height,valid,newhwm=0,flag = 0; bits256 hash2; char hashstr[65]; struct iguana_block *block;
    flag = iguana_processbundlesQ(coin,&newhwm);
     //if ( newhwm != 0 )
    //    flag += iguana_lookahead(coin,&hash2,coin->blocks.hwmheight);
    while ( iguana_recvblock(coin,coin->blocks.recvblocks) != 0 )
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
        if ( (coin->bcount > 1 || time(NULL) > coin->recvtime) && iguana_recvblock(coin,coin->blocks.recvblocks) == 0 && coin->blocks.recvblocks < coin->blocks.hashblocks )
        {
            hash2 = iguana_blockhash(coin,&valid,coin->blocks.recvblocks);
            flag += (iguana_queueblock(coin,coin->blocks.recvblocks,hash2,1) > 0);
            coin->recvtime = (uint32_t)time(NULL);
        }
    } else coin->pcount = 0;
    if ( queue_size(&coin->blocksQ) == 0 )
    {
        coin->bcount++;
        if ( coin->bcount > 1 || time(NULL) > coin->recvtime )
        {
            for (height=coin->blocks.recvblocks+1; height<coin->blocks.issuedblocks; height++)
            {
                if ( iguana_recvblock(coin,coin->blocks.recvblocks) == 0 )
                {
                    printf("RETRY BLOCK.%d\n",height);
                    flag += (iguana_queueblock(coin,height,iguana_blockhash(coin,&valid,height),0) > 0);
                }
            }
            coin->recvtime = (uint32_t)time(NULL);
        }
    } else coin->bcount = 0;
    return(flag);
}

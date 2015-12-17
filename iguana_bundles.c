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

int32_t iguana_hash2set(struct iguana_info *coin,char *str,bits256 *orighash2,bits256 newhash2)
{
    if ( bits256_nonz(newhash2) == 0 )
    {
        printf("iguana_hash2set warning: newhash2 is zero\n"), getchar();
        return(-1);
    }
    if ( bits256_nonz(*orighash2) > 0 )
    {
        if ( memcmp(newhash2.bytes,orighash2,sizeof(bits256)) != 0 )
        {
            char str2[65],str3[65];
            bits256_str(str2,*orighash2), bits256_str(str2,newhash2);
            printf("iguana_hash2set overwrite [%s] %s with %s\n",str,str2,str3);
            if ( strcmp(str,"firstblockhash2") == 0 )
                getchar();
            *orighash2 = newhash2;
            return(-1);
        }
    }
    *orighash2 = newhash2;
    return(0);
}

bits256 iguana_bundleihash2(struct iguana_info *coin,struct iguana_bundle *bp,int32_t bundlei)
{
    struct iguana_block *block; bits256 zero;
    if ( bp->hdrsi == 0 && bp->bundleheight == 0 && bundlei == 0 )
        return(*(bits256 *)coin->chain->genesis_hashdata);
    memset(zero.bytes,0,sizeof(zero));
    if ( bundlei < -1 )
        return(zero);
    else if ( bundlei == -1 )
        return(bp->prevbundlehash2);
    else if ( bundlei == 0 )
        return(bp->bundlehash2);
    else if ( bundlei == 1 )
        return(bp->firstblockhash2);
    else if ( bundlei >= bp->n )
        return(bp->nextbundlehash2);
    else if ( bp->blockhashes != 0 && (block= bp->blocks[bundlei]) != 0 )
    {
        if ( memcmp(bp->blockhashes[bundlei].bytes,block->hash2.bytes,sizeof(bits256)) != 0 )
        {
            char str[65],str2[65];
            bits256_str(str,bp->blockhashes[bundlei]), bits256_str(str2,block->hash2);
            printf("bundleihash2 error at bundlei.%d %s != %s\n",bundlei,str,str2);
            return(zero);
        }
        return(bp->blockhashes[bundlei]);
    }
    else if ( (block= bp->blocks[bundlei]) != 0 )
        return(block->hash2);
    else if ( bp->blockhashes != 0 )
        return(bp->blockhashes[bundlei]);
    else return(zero);
}

struct iguana_bundle *iguana_bundlescan(struct iguana_info *coin,int32_t *bundleip,struct iguana_bundle *bp,bits256 hash2,int32_t searchmask)
{
    int32_t i;
    *bundleip = -2;
    if ( (searchmask & IGUANA_SEARCHBUNDLE) != 0 )
    {
        // bloom filter here
        //printf("%s vs %s: %d\n",bits256_str(hash2),bits256_str2(bp->bundlehash2),memcmp(hash2.bytes,bp->bundlehash2.bytes,sizeof(hash2)));
        if ( memcmp(hash2.bytes,bp->bundlehash2.bytes,sizeof(hash2)) == 0 )
        {
            if ( bp->blockhashes != 0 )
                iguana_hash2set(coin,"blockhashes[0]",&bp->blockhashes[0],bp->bundlehash2);
            *bundleip = 0;
            return(bp);
        }
        if ( memcmp(hash2.bytes,bp->firstblockhash2.bytes,sizeof(hash2)) == 0 )
        {
            if ( bp->blockhashes != 0 )
                iguana_hash2set(coin,"blockhashes[1]",&bp->blockhashes[1],bp->firstblockhash2);
            *bundleip = 1;
            return(bp);
        }
        if ( bp->blockhashes != 0 )
        {
            /*if ( bits256_nonz(bp->lastblockhash2) > 0 )
             iguana_hash2set(coin,"blockhashes[n-1]",&bp->blockhashes[bp->n-1],bp->lastblockhash2);
             else if ( bits256_nonz(bp->blockhashes[bp->n-1]) > 0 )
             iguana_hash2set(coin,"b blockhashes[n-1]",&bp->lastblockhash2,bp->blockhashes[bp->n-1]);
             
             if ( (searchmask & IGUANA_SEARCHNOLAST) == 0 )
             {
             if ( memcmp(hash2.bytes,bp->lastblockhash2.bytes,sizeof(hash2)) == 0 )
             {
             *bundleip = bp->n - 1;
             return(bp);
             }
             }*/
            //printf("blockhashes.%p n.%d\n",bp->blockhashes,bp->n);
            for (i=1; i<bp->n && i<coin->chain->bundlesize; i++)
            {
                if ( memcmp(hash2.bytes,bp->blockhashes[i].bytes,sizeof(hash2)) == 0 )
                {
                    *bundleip = i;
                    return(bp);
                }
            }
        }
    }
    if ( (searchmask & IGUANA_SEARCHPREV) != 0 && memcmp(hash2.bytes,bp->prevbundlehash2.bytes,sizeof(hash2)) == 0 )
    {
        *bundleip = -1;
        return(bp);
    }
    if ( (searchmask & IGUANA_SEARCHNEXT) != 0 && memcmp(hash2.bytes,bp->nextbundlehash2.bytes,sizeof(hash2)) == 0 )
    {
        *bundleip = bp->n;
        return(bp);
    }
    return(0);
}

struct iguana_bundle *iguana_bundlefind(struct iguana_info *coin,int32_t *bundleip,bits256 hash2,int32_t adjust)
{
    int32_t i,searchmask; struct iguana_bundle *bp = 0; // struct iguana_block *block;
    *bundleip = -2;
    if ( bits256_nonz(hash2) > 0 )
    {
        if ( adjust == 0 )
            searchmask = IGUANA_SEARCHBUNDLE;
        else searchmask = IGUANA_SEARCHNOLAST;
        //if ( (block= iguana_blockfind(coin,hash2)) != 0 && (bp= block->bp) != 0 && (bp= iguana_bundlescan(coin,bundleip,bp,hash2,searchmask)) != 0 )
        //    return(bp);
        for (i=0; i<coin->bundlescount; i++)
        {
            if ( (bp= coin->bundles[i]) != 0 )
            {
                if ( (bp= iguana_bundlescan(coin,bundleip,bp,hash2,searchmask)) != 0 )
                    return(bp);
            }
        }
    }
    //printf("iguana_hdrsfind: cant find %s\n",bits256_str(hash2));
    return(0);
}

struct iguana_bundle *iguana_bundlesearch(struct iguana_info *coin,int32_t *bundleip,bits256 hash2)
{
    int32_t j; struct iguana_bundle *bp;
    for (j=0; j<coin->bundlescount; j++)
    {
        if ( (bp= coin->bundles[j]) != 0 )
        {
            if ( (bp= iguana_bundlescan(coin,bundleip,bp,hash2,IGUANA_SEARCHBUNDLE)) != 0 )
                return(bp);
        }
    }
    return(0);
}

struct iguana_block *iguana_bundleblockadd(struct iguana_info *coin,struct iguana_bundle *bp,int32_t bundlei,bits256 hash2)
{
    struct iguana_block *block =0; struct iguana_bundle *prevbp,*nextbp; int32_t i,nextbundlei; bits256 cmphash2;
    if ( bits256_nonz(hash2) > 0 && (block= iguana_blockhashset(coin,-1,hash2,1)) != 0 )
    {
        if ( bundlei >= coin->chain->bundlesize )
            return(block);
        block->hdrsi = bp->hdrsi;
        //printf("iguana_bundleblockadd[%d] %d <- %s\n",bp->hdrsi,bundlei,bits256_str(hash2));
        /*if ( bundlei < bp->n-1 )
         {
         iguana_hash2set(coin,"block bundlehash2",&block->bundlehash2,bp->bundlehash2);
         if ( block->bp != 0 && block->bp != bp )
         printf("bundleblockadd: REPLACE %s.bp %p <- %p\n",bits256_str(block->hash2),block->bp,bp);
         block->bp = bp;
         }*/
        if ( (block->bundlei= bundlei) == 0 )
        {
            iguana_hash2set(coin,"bundlehash2",&bp->bundlehash2,block->hash2);
            //iguana_blockQ(coin,bp,0,bp->bundlehash2,1);
            if ( bp->blockhashes != 0 )
                iguana_hash2set(coin,"blockhashes[0]",&bp->blockhashes[0],bp->bundlehash2);
            if ( bits256_nonz(block->prev_block) > 0 )
            {
                //iguana_blockQ(coin,bp,-1,block->prev_block,1);
                for (i=0; i<coin->bundlescount; i++)
                {
                    if ( (prevbp= coin->bundles[i]) != 0 && prevbp->n >= coin->chain->bundlesize )
                    {
                        cmphash2 = iguana_bundleihash2(coin,prevbp,coin->chain->bundlesize-1);
                        if ( memcmp(cmphash2.bytes,block->prev_block.bytes,sizeof(bits256)) == 0 )
                        {
                            //printf("found prev_block\n");
                            iguana_hash2set(coin,"bp setprev",&bp->prevbundlehash2,prevbp->bundlehash2);
                            iguana_hash2set(coin,"prevbp setnext",&prevbp->nextbundlehash2,bp->bundlehash2);
                            //printf("prev BUNDLES LINKED! (%d <-> %d) (%s <-> %s)\n",prevbp->bundleheight,bp->bundleheight,bits256_str(prevbp->bundlehash2),bits256_str2(bp->bundlehash2));
                            if ( prevbp->bundleheight != bp->bundleheight-coin->chain->bundlesize )
                                printf("WARNING gap in bundleheight %d != %d bundlesize\n",prevbp->bundleheight,bp->bundleheight-coin->chain->bundlesize);
                            break;
                        }
                    }
                }
            }
        }
        else if ( bundlei == 1 )
        {
            iguana_hash2set(coin,"firstblockhash2",&bp->firstblockhash2,block->hash2);
            if ( bp->blockhashes != 0 )
            {
                if ( bits256_nonz(block->prev_block) > 0 )
                    iguana_hash2set(coin,"b blockhashes[0]",&bp->blockhashes[0],block->prev_block);
                iguana_hash2set(coin,"b blockhashes[1]",&bp->blockhashes[1],block->hash2);
            }
        }
        else if ( bundlei == bp->n-1 )
        {
            if ( (nextbp= iguana_bundlefind(coin,&nextbundlei,hash2,-1)) != 0 )
            {
                if ( nextbundlei == 0 )
                {
                    iguana_hash2set(coin,"bp setnext",&bp->nextbundlehash2,nextbp->bundlehash2);
                    iguana_hash2set(coin,"next setprev",&bp->prevbundlehash2,bp->bundlehash2);
                    char str[65],str2[65];
                    bits256_str(str,bp->bundlehash2), bits256_str(str2,nextbp->bundlehash2);
                    printf("next BUNDLES LINKED! (%d <-> %d) (%s <-> %s)\n",bp->bundleheight,nextbp->bundleheight,str,str2);
                    if ( nextbp->bundleheight != bp->bundleheight+coin->chain->bundlesize )
                        printf("WARNING gap in bundleheight %d != %d bundlesize\n",nextbp->bundleheight,bp->bundleheight+coin->chain->bundlesize);
                } else printf("nextbundlei.%d != 0 nextbp->n %d\n",nextbundlei,nextbp->n);
            }
            //iguana_hash2set(coin,"lastblockhash2",&bp->lastblockhash2,block->hash2);
        }
    }
    return(block);
}

struct iguana_bundle *iguana_bundlecreate(struct iguana_info *coin,bits256 bundlehash2,bits256 firstblockhash2)
{
    struct iguana_bundle *bp = 0; int32_t bundlei = -2;
    if ( (bp= iguana_bundlefind(coin,&bundlei,bundlehash2,-1)) != 0 )
    {
        //printf("found bundlehash.%s bundlei.%d bp.%p %d\n",bits256_str(bundlehash2),*bundleip,bp,bp->hdrsi);
        return(bp);
    }
    if ( (bp= iguana_bundlefind(coin,&bundlei,firstblockhash2,-1)) != 0 )
    {
        //printf("found firstblockhash2.%s bundlei.%d bp.%p %d\n",bits256_str(firstblockhash2),*bundleip,hdrs,hdrs->hdrsi);
        return(bp);
    }
    // printf("search miss\n");
    if ( bits256_nonz(bundlehash2) > 0 )
    {
        //coin->bundles = myrealloc('W',coin->bundles,coin->bundles==0?0:coin->numhdrs*sizeof(*coin->bundles),(coin->numhdrs+1)*sizeof(*coin->bundles));
        bp = mycalloc('b',1,sizeof(*bp) + (1+coin->chain->bundlesize)*sizeof(*bp->issued)); //&coin->bundles[coin->numhdrs];
        bp->blocks = mycalloc('k',sizeof(*bp->blocks),(1+coin->chain->bundlesize));
        bp->hdrsi = coin->bundlescount;
        bp->bundlehash2 = bundlehash2;
        bp->coin = coin;
        bp->avetime = coin->avetime * 2.;
        bp->firstblockhash2 = firstblockhash2;
        bp->bundleheight = -1;
        coin->bundles[coin->bundlescount++] = bp;
        char str[65],str2[65];
        bits256_str(str,bundlehash2), bits256_str(str2,firstblockhash2);
        printf("alloc.[%d] new hdrs.%s first.%s %p\n",coin->bundlescount,str,str2,bp);
        //if ( bits256_nonz(bundlehash2) > 0 )
        //    iguana_blockQ(coin,bp,0,bundlehash2,1);
        //if ( bits256_nonz(firstblockhash2) > 0 )
        //    iguana_blockQ(coin,bp,1,firstblockhash2,1);
        return(bp);
    }
    //else printf("iguana_hdrscreate cant find hdr with %s or %s\n",bits256_str(bundlehash2),bits256_str2(firstblockhash2));
    return(0);
}

struct iguana_block *iguana_recvblockhdr(struct iguana_info *coin,struct iguana_bundle **bpp,int32_t *bundleip,struct iguana_block *block,int32_t *newhwmp)
{
    struct iguana_bundle *prevbp,*bp = 0; int32_t i,j,prevbundlei; bits256 orighash2 = block->hash2;
    (*bpp) = 0;
    *bundleip = -2;
    if ( (block= iguana_blockhashset(coin,-1,block->hash2,1)) == 0 )
    {
        char str[65];
        bits256_str(str,orighash2);
        printf("error getting block for %s\n",str);
        return(0);
    }
    if ( (bp= iguana_bundlefind(coin,bundleip,block->hash2,-1)) == 0 )
    {
        if ( (prevbp= iguana_bundlefind(coin,&prevbundlei,block->prev_block,-1)) == 0 )
        {
            for (j=0; j<coin->bundlescount; j++)
            {
                if ( (bp= coin->bundles[j]) != 0 )
                {
                    if ( (bp= iguana_bundlescan(coin,bundleip,bp,block->hash2,IGUANA_SEARCHNOLAST)) != 0 )
                    {
                        (*bpp) = bp;
                        char str[65];
                        bits256_str(str,block->hash2);
                        printf("FOUND.%s in bundle.[%d:%d] %d\n",str,bp->hdrsi,*bundleip,bp->bundleheight + *bundleip);
                        iguana_bundleblockadd(coin,bp,*bundleip,block->hash2);
                        return(block);
                    }
                }
            }
            char str[65];
            bits256_str(str,block->hash2);
            printf("CANTFIND.%s\n",str);
            return(block);
        }
        else
        {
            (*bpp) = bp;
            char str[65];
            if ( prevbundlei >= 0 && prevbundlei < coin->chain->bundlesize-1 )
            {
                *bundleip = prevbundlei + 1;
                bits256_str(str,block->hash2);
                printf("prev FOUND.%s in bundle.[%d:%d] %d\n",str,bp->hdrsi,*bundleip,bp->bundleheight + *bundleip);
                iguana_bundleblockadd(coin,bp,*bundleip,block->hash2);
            }
            if ( prevbundlei == coin->chain->bundlesize-1 )
            {
                bits256 zero;
                memset(zero.bytes,0,sizeof(zero));
                bits256_str(str,block->hash2);
                printf("prev AUTOCREATE.%s\n",str);
                iguana_bundlecreate(coin,block->hash2,zero);
            }
            return(block);
        }
    }
    else
    {
        (*bpp) = bp;
        //printf("blockadd.%s %s %d\n",bits256_str(block->hash2),bits256_str2(orighash2),*bundleip);
        iguana_bundleblockadd(coin,bp,*bundleip,block->hash2);
        if ( *bundleip > 0 && bits256_nonz(block->prev_block) > 0 )
            iguana_bundleblockadd(coin,bp,(*bundleip) - 1,block->prev_block);
        if ( bp->hdrsi < coin->bundlescount/2 && *bundleip == bp->n-1 )
        {
            printf("Q all of hdrs.%d\n",bp->hdrsi);
            for (i=0; i<bp->n && i<coin->chain->bundlesize; i++)
                if ( bp->blocks[i] != 0 )
                    iguana_blockQ(coin,bp,i,bp->blocks[i]->hash2,bp->hdrsi < coin->bundlescount/4);
        }
    }
    return(block);
}

struct iguana_bundlereq *iguana_recvblockhashes(struct iguana_info *coin,struct iguana_bundlereq *req,bits256 *blockhashes,int32_t num)
{
    struct iguana_bundle *bp; int32_t i,j,missing,bundlei = -2,bundleheight = -1;
    if ( (bp= iguana_bundlefind(coin,&bundlei,blockhashes[1],-1)) != 0 )
    {
        if ( bp->blockhashes == 0 )
        {
            bundleheight = bp->bundleheight;
            if ( num > coin->chain->bundlesize+1 )
            {
                bp->blockhashes = mycalloc('h',coin->chain->bundlesize+1,sizeof(*blockhashes));
                memcpy(bp->blockhashes,blockhashes,(coin->chain->bundlesize+1) * sizeof(*blockhashes));
                num = coin->chain->bundlesize+1;
            } else bp->blockhashes = req->hashes, req->hashes = 0;
            //printf("GOT blockhashes.%s[%d] %d %p hdrsi.%d\n",bits256_str(blockhashes[1]),num,bundleheight,bp->blockhashes,bp->hdrsi);
            bp->n = num;
            bp->bundleheight = bundleheight;
            if ( bundlei >= 0 && bundlei < bp->n )
            {
                j = 1;
                char str[65];
                bits256_str(str,blockhashes[1]);
                if ( bundlei != 1 )
                    printf(">>>>>>>>> %s bundlei.%d j.%d\n",str,bundlei,j);
                for (i=bundlei; i<bp->n&&j<bp->n&&i<coin->chain->bundlesize; i++,j++)
                    iguana_bundleblockadd(coin,bp,i,blockhashes[j]);
            }
            //iguana_blockQ(coin,bp,1,blockhashes[1],1);
            //if ( bp->n < coin->chain->bundlesize )
            //    iguana_blockQ(coin,bp,bp->n-1,blockhashes[bp->n-1],1);
            //else iguana_blockQ(coin,bp,coin->chain->bundlesize-1,blockhashes[coin->chain->bundlesize-1],1);
        }
        else
        {
            if ( num > 2 )
            {
                for (i=missing=0; i<num && i<bp->n && i<coin->chain->bundlesize; i++)
                {
                    if ( iguana_bundlescan(coin,&bundlei,bp,blockhashes[i],IGUANA_SEARCHBUNDLE) == 0 )
                    {
                        missing++;
                    }
                }
                if ( missing != 0 )
                {
                    //printf("GOT MISMATCHED %d blockhashes.%s[%d] missing.%d of %d\n",bp->bundleheight,bits256_str(blockhashes[1]),num,missing,bp->n);
                    return(req);
                }
                if ( num > bp->n && bp->n <= coin->chain->bundlesize )
                {
                    /*myfree(bp->blockhashes,sizeof(*bp->blockhashes) * bp->n);
                     bp->blockhashes = mycalloc('h',num,sizeof(*blockhashes));
                     printf("replace blockhashes.%s[%d] %d %p\n",bits256_str(blockhashes[0]),num,bp->bundleheight,bp->blockhashes);
                     memcpy(bp->blockhashes,blockhashes,num * sizeof(*blockhashes));
                     i = bp->n, bp->n = num;
                     for (; i<num; i++)
                     iguana_bundleblockadd(coin,bp,i,blockhashes[i]);*/
                    return(req);
                }
                char str[65];
                bits256_str(str,blockhashes[1]);
                if ( bp->bundleheight >= 0 && (rand() % 1000) == 0 )
                    printf("GOT duplicate.%s[%d] bheight.%d\n",str,num,bp->bundleheight);
            }
        }
        if ( (num= bp->n) > coin->chain->bundlesize )
            num = coin->chain->bundlesize;
    }
    else
    {
        if ( num > coin->chain->bundlesize+1 )
            num = coin->chain->bundlesize+1;
        for (i=1; i<num; i++)
            iguana_blockhashset(coin,-1,blockhashes[i],1);
        if ( num > 2 )
        {
            char str[65];
            bits256_str(str,blockhashes[1]);
            printf("recvblockhashes cant find %s num.%d\n",str,num);
            iguana_bundlecreate(coin,blockhashes[1],blockhashes[2]);
            if ( 0 && num == coin->chain->bundlesize+1 && iguana_bundlefind(coin,&bundlei,blockhashes[num - 1],0) == 0 )
            {
                bits256 zero;
                memset(zero.bytes,0,sizeof(zero));
                bits256_str(str,blockhashes[num - 1]);
                printf("AUTO EXTEND2.%s[%d]\n",str,num);
                iguana_bundlecreate(coin,blockhashes[num - 1],zero);
            }
        }
    }
    return(req);
}

struct iguana_bundlereq *iguana_recvblockhdrs(struct iguana_info *coin,struct iguana_bundlereq *req,struct iguana_block *blocks,int32_t n,int32_t *newhwmp)
{
    int32_t i,j; struct iguana_block *block; struct iguana_bundle *bp; bits256 *blockhashes;
    if ( blocks == 0 )
        return(req);
    if ( n > coin->chain->bundlesize+1 )
        n = coin->chain->bundlesize+1;
    blockhashes = mycalloc('h',n+1,sizeof(*blockhashes));
    blockhashes[0] = blocks->prev_block;
    for (i=0; i<n; i++)
        blockhashes[i+1] = blocks[i].hash2;
    n++;
    for (j=0; j<coin->bundlescount; j++)
    {
        if ( (bp= coin->bundles[j]) != 0 )
        {
            if ( memcmp(blocks[0].prev_block.bytes,bp->bundlehash2.bytes,sizeof(bits256)) == 0 )
            {
                iguana_hash2set(coin,"blockhdrs[1]",&bp->firstblockhash2,blocks[0].hash2);
                if ( bp->blockhashes == 0 )
                {
                    bp->blockhashes = blockhashes;
                    bp->n = n;
                    for (i=1; i<n; i++)
                        if ( (block= iguana_blockfind(coin,blockhashes[i])) != 0 )
                            iguana_copyblock(coin,block,&blocks[i-1]);
                    /*iguana_blockQ(coin,bp,0,bp->bundlehash2,1);
                    iguana_blockQ(coin,bp,1,blockhashes[1],1);
                    if ( bp->n < coin->chain->bundlesize )
                        iguana_blockQ(coin,bp,n-1,blockhashes[n-1],1);
                    else iguana_blockQ(coin,bp,coin->chain->bundlesize-1,blockhashes[coin->chain->bundlesize-1],1);*/
                    break;
                }
                else
                {
                    //printf("free duplicate blockhashes\n");
                    myfree(blockhashes,n*sizeof(*blockhashes));
                }
            }
        }
    }
    return(req);
}

void iguana_gotdata(struct iguana_info *coin,struct iguana_peer *addr,int32_t height,bits256 hash2)
{
    if ( addr != 0 && height > addr->height && height < coin->longestchain )
    {
        iguana_set_iAddrheight(coin,addr->ipbits,height);
        addr->height = height;
    }
}

struct iguana_bundlereq *iguana_recvblock(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_bundlereq *req,struct iguana_block *origblock,int32_t numtx,int32_t datalen,int32_t *newhwmp)
{
    struct iguana_bundle *bp; int32_t bundlei; struct iguana_block *block; double duration = 0.;
    if ( (block= iguana_recvblockhdr(coin,&bp,&bundlei,origblock,newhwmp)) != 0 )
    {
        iguana_copyblock(coin,block,origblock);
        //printf("iguana_recvblock (%s) %d[%d] bit.%d recv.%d %02x %02x\n",bits256_str(block->hash2),bp->hdrsi,bundlei,GETBIT(bp->recv,bundlei),bp->numrecv,bp->recv[0],bp->recv[bp->n/8]);
        if ( bp != 0 && datalen > 0 )
        {
            //printf("iguana_recvblock (%s) %d[%d] bit.%d recv.%d %02x %02x\n",bits256_str(block->hash2),bp->hdrsi,bundlei,GETBIT(bp->recv,bundlei),bp->numrecv,bp->recv[0],bp->recv[bp->n/8]);
            SETBIT(bp->recv,bundlei);
            if ( bp->issued[bundlei] > 0 )
            {
                duration = (int32_t)(milliseconds() - bp->issued[bundlei]);
                if ( duration < bp->avetime/10. )
                    duration = bp->avetime/10.;
                else if ( duration > bp->avetime*10. )
                    duration = bp->avetime * 10.;
                dxblend(&bp->avetime,duration,.9);
                dxblend(&coin->avetime,bp->avetime,.9);
            }
            //if ( bundlei == 1 )
            //    iguana_blockQ(coin,bp,0,block->prev_block,1);
            if ( req->addr != 0 && req->addr->ipbits != 0 && req->addr->addrind != 0 && bundlei >= 0 && bundlei < bp->n && bundlei < coin->chain->bundlesize )
            {
                block->ipbits = req->addr->ipbits;
                block->recvlen = datalen;
                bp->blocks[bundlei] = block;
                bp->numrecv++;
                //iguana_txdataQ(coin,req,bp,bundlei);
            }
            
            //printf("%s hdrsi.%d recv[%d] dur.%.0f avetimes.(%.2f %.2f) numpendinds.%d %f\n",bits256_str(block->hash2),hdrs->hdrsi,bundlei,duration,hdrs->avetime,coin->avetime,coin->numpendings,hdrs->issued[bundlei]);
        }
    }
    else //if ( (rand() % 100) == 0 )
        printf("cant create block.%llx\n",(long long)origblock->hash2.txid);
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

char *iguana_bundledisp(struct iguana_info *coin,struct iguana_bundle *prevbp,struct iguana_bundle *bp,struct iguana_bundle *nextbp,int32_t m)
{
    static char line[1024];
    line[0] = 0;
    if ( bp == 0 )
        return(line);
    if ( prevbp != 0 )
    {
        if ( memcmp(prevbp->bundlehash2.bytes,bp->prevbundlehash2.bytes,sizeof(bits256)) == 0 )
        {
            if ( memcmp(prevbp->nextbundlehash2.bytes,bp->bundlehash2.bytes,sizeof(bits256)) == 0 )
                sprintf(line+strlen(line),"<->");
            else sprintf(line+strlen(line),"<-");
        }
        else if ( memcmp(prevbp->nextbundlehash2.bytes,bp->bundlehash2.bytes,sizeof(bits256)) == 0 )
            sprintf(line+strlen(line),"->");
    }
    sprintf(line+strlen(line),"(%d:%d)",bp->hdrsi,m);
    if ( nextbp != 0 )
    {
        if ( memcmp(nextbp->bundlehash2.bytes,bp->nextbundlehash2.bytes,sizeof(bits256)) == 0 )
        {
            if ( memcmp(nextbp->prevbundlehash2.bytes,bp->bundlehash2.bytes,sizeof(bits256)) == 0 )
                sprintf(line+strlen(line),"<->");
            else sprintf(line+strlen(line),"->");
        }
        else if ( memcmp(nextbp->prevbundlehash2.bytes,bp->bundlehash2.bytes,sizeof(bits256)) == 0 )
            sprintf(line+strlen(line),"<-");
    }
    return(line);
}

int32_t iguana_bundlecheck(struct iguana_info *coin,struct iguana_bundle *bp,int32_t priorityflag)
{
    int32_t i,qsize,remains,incomplete,lasti,n = 0; struct iguana_block *block;
    bits256 hash2; double threshold; uint64_t datasize =0;
    //printf("bp.%p bundlecheck.%d emit.%d\n",bp,bp->hdrsi,bp->emitfinish);
    if ( bp != 0 && bp->emitfinish == 0 )
    {
        remains = bp->n - bp->numrecv;
        qsize = queue_size(&coin->priorityQ);
        if ( bp->numrecv > coin->chain->bundlesize*.98 )
        {
            priorityflag = 1;
            if ( bp->numrecv > coin->chain->bundlesize-3 )
                threshold = bp->avetime;
            else threshold = bp->avetime * 2;
        } else threshold = bp->avetime * 5;
        lasti = -1;
        for (i=0; i<coin->chain->bundlesize; i++)
        {
            hash2 = iguana_bundleihash2(coin,bp,i);
            if ( bits256_nonz(hash2) == 0 )
                continue;
            if ( (block= bp->blocks[i]) == 0 )
                block = bp->blocks[i] = iguana_blockfind(coin,hash2);
            if ( block != 0 && block->ipbits != 0 )
            {
                //char str[65];
                if ( block->recvlen != 0 )
                    datasize += block->recvlen;
                if ( block->hdrsi != bp->hdrsi )
                    block->hdrsi = bp->hdrsi;
                if ( block->bundlei != i )
                    block->bundlei = i;
                /*    printf("%s %d[%d] != %d[%d]\n",bits256_str(str,block->hash2),block->hdrsi,block->bundlei,bp->hdrsi,i);
                    CLEARBIT(bp->recv,i);
                    //memset(&bp->blocks[i]->txdatabits,0,sizeof(bp->blocks[i]->txdatabits));
                    bp->issued[i] = milliseconds();
                    iguana_blockQ(coin,bp,i,bp->blocks[i]->hash2,1);
                    bp->blocks[i] = 0;
                }
                else if ( block->bundlei != i )
                {
                    printf("%s %d[%d] != %d[%d]\n",bits256_str(str,block->hash2),block->hdrsi,block->bundlei,bp->hdrsi,i);
                    CLEARBIT(bp->recv,i);
                    //memset(&bp->blocks[i]->txdatabits,0,sizeof(bp->blocks[i]->txdatabits));
                    bp->issued[i] = milliseconds();
                    iguana_blockQ(coin,bp,i,bp->blocks[i]->hash2,1);
                    bp->blocks[i] = 0;
                } else */
                n++;
            }
            else if ( priorityflag != 0 && qsize == 0 && (bp->issued[i] == 0 || milliseconds() > (bp->issued[i] + threshold)) )
            {
                if ( (rand() % 1000) == 0 )
                    printf("priorityQ submit threshold %.3f [%d].%d\n",threshold,bp->hdrsi,i);
                CLEARBIT(bp->recv,i);
                bp->issued[i] = milliseconds();
                iguana_blockQ(coin,bp,i,hash2,priorityflag);
                bp->blocks[i] = 0;
                lasti = i;
            } else lasti = i;
        }
        //if ( n == coin->chain->bundlesize-1 )
        //    printf("bp.%d %d %d\n",bp->hdrsi,bp->bundleheight,lasti);
        bp->numrecv = n;
        bp->datasize = datasize;
        if ( n > 0 )
        {
            bp->estsize = ((uint64_t)datasize * coin->chain->bundlesize) / n;
            //printf("estsize %d datasize.%d hdrsi.%d numrecv.%d\n",(int32_t)bp->estsize,(int32_t)datasize,bp->hdrsi,n);
        }
        if ( n == coin->chain->bundlesize )
        {
            //printf("check %d blocks in hdrs.%d\n",n,bp->hdrsi);
            for (i=incomplete=0; i<n-1; i++)
            {
                if ( memcmp(bp->blocks[i]->hash2.bytes,bp->blocks[i+1]->prev_block.bytes,sizeof(bits256)) != 0 )
                {
                    if ( bits256_nonz(bp->blocks[i]->prev_block) > 0 && bits256_nonz(bp->blocks[i+1]->prev_block) > 0 && bits256_nonz(bp->blocks[i+1]->hash2) > 0 )
                    {
                        char str[65],str2[65],str3[65];
                        bits256_str(str,bp->blocks[i]->hash2);
                        bits256_str(str2,bp->blocks[i+1]->prev_block);
                        bits256_str(str3,bp->blocks[i+1]->hash2);
                        printf("%s ->%d %d<- %s %s ",str,i,i+1,str2,str3);
                        printf("broken chain in hdrs.%d %d %p <-> %p %d\n",bp->hdrsi,i,bp->blocks[i],bp->blocks[i+1],i+1);
                        CLEARBIT(bp->recv,i);
                        //memset(&bp->blocks[i]->txdatabits,0,sizeof(bp->blocks[i]->txdatabits));
                        //memset(&bp->blocks[i+1]->txdatabits,0,sizeof(bp->blocks[i+1]->txdatabits));
                        bp->issued[i] = bp->issued[i+1] = milliseconds();
                        //iguana_blockQ(coin,bp,i,bp->blocks[i]->hash2,1);
                        //iguana_blockQ(coin,bp,i+1,bp->blocks[i+1]->hash2,1);
                        bp->blocks[i] = bp->blocks[i+1] = 0;
                        break;
                    }
                    else incomplete++;
                }
            }
            if ( i == n-1 && incomplete == 0 )
            {
                if ( bp->blockhashes != 0 )
                {
                    for (i=0; i<n; i++)
                        iguana_hash2set(coin,"check blocks",&bp->blockhashes[i],bp->blocks[i]->hash2);
                    iguana_hash2set(coin,"check bundlehash2",&bp->blockhashes[0],bp->bundlehash2);
                    iguana_hash2set(coin,"check firsthash2",&bp->blockhashes[1],bp->firstblockhash2);
                }
                iguana_bundleblockadd(coin,bp,0,iguana_bundleihash2(coin,bp,0));
                iguana_bundleblockadd(coin,bp,coin->chain->bundlesize-1,iguana_bundleihash2(coin,bp,coin->chain->bundlesize-1));
                if ( bp->emitfinish <= 1 )
                    iguana_emitQ(coin,bp);
                if ( bp->emitfinish == 0 )
                    bp->emitfinish = 1;
                coin->numpendings--;
                return(1);
            }
        }
    }
    return(0);
}

int32_t iguana_issueloop(struct iguana_info *coin)
{
    static uint32_t lastdisp;
    int32_t i,closestbundle,bundlei,qsize,RTqsize,m,numactive,numwaiting,maxwaiting,lastbundle,n,dispflag = 0,flag = 0;
    int64_t remaining,closest; struct iguana_bundle *bp,*prevbp,*nextbp; bits256 hash2; struct iguana_block *block;
    if ( time(NULL) > lastdisp+13 )
    {
        dispflag = 1;
        lastdisp = (uint32_t)time(NULL);
    }
    qsize = queue_size(&coin->blocksQ);
    if ( qsize == 0 )
        coin->bcount++;
    else coin->bcount = 0;
    maxwaiting = (coin->MAXBUNDLES * coin->chain->bundlesize);
    numwaiting = 0;
    numactive = 0;
    prevbp = nextbp = 0;
    lastbundle = -1;
    for (i=coin->bundlescount-1; i>=0; i--)
        if ( (bp= coin->bundles[i]) != 0 && bp->emitfinish == 0 && bp->blockhashes != 0 )
        {
            lastbundle = i;
            break;
        }
    if ( lastbundle != coin->lastbundle )
        coin->lastbundletime = (uint32_t)time(NULL);
    //coin->lastbundle = lastbundle;
    //if ( 0 && time(NULL) < coin->starttime+60 )
    lastbundle = -1;
    n = 0;
    closest = closestbundle = -1;
    for (i=0; i<coin->bundlescount; i++)
    {
        qsize = queue_size(&coin->blocksQ);
        m = 0;
        if ( (bp= coin->bundles[i]) != 0 )
        {
            nextbp = (i < coin->bundlescount-1) ? coin->bundles[i+1] : 0;
            if ( bp->emitfinish == 0 )
            {
                iguana_bundlecheck(coin,bp,numactive == 0 || i == coin->closestbundle || i == lastbundle);
                if ( bp->numrecv > 3 || numactive == 0 )
                {
                    numactive++;
                    remaining = (bp->estsize - bp->datasize) + (rand() % (1 + bp->estsize))/100;
                    if ( remaining > 0 && (closest < 0 || remaining < closest) )
                    {
                        //printf("closest.[%d] %d -> R.%d (%d - %d)\n",closestbundle,(int)closest,(int)remaining,(int)bp->estsize,(int)bp->datasize);
                        closest = remaining;
                        closestbundle = i;
                    }
                }
                if (  i > (coin->numemitted+coin->MAXPENDING) && numactive >= coin->MAXPENDING && i != coin->closestbundle && i != lastbundle )
                    continue;
                RTqsize = queue_size(&coin->blocksQ);
                for (bundlei=0; bundlei<bp->n && bundlei<coin->chain->bundlesize; bundlei++)
                {
                    if ( (block= bp->blocks[bundlei]) != 0 && block->ipbits != 0 )
                    {
                        m++;
                        //printf("hashes.%p numrecv.%d hdrs->n.%d qsize.%d\n",bp->blockhashes,bp->numrecv,bp->n,qsize);
                        continue;
                    }
                    hash2 = iguana_bundleihash2(coin,bp,bundlei);
                    if ( bits256_nonz(hash2) > 0 )
                    {
                        //printf("hdrsi.%d qsize.%d bcount.%d check bundlei.%d bit.%d %.3f lag %.3f ave %.3f\n",bp->hdrsi,qsize,coin->bcount,bundlei,GETBIT(bp->recv,bundlei),bp->issued[bundlei],milliseconds() - bp->issued[bundlei],bp->avetime);
                        if ( GETBIT(bp->recv,bundlei) == 0 )
                        {
                            if ( bp->issued[bundlei] > SMALLVAL )
                                numwaiting++;
                            if ( bp->issued[bundlei] == 0 || (qsize == 0 && coin->bcount > 100 && milliseconds() > (bp->issued[bundlei] + bp->avetime*2)) )
                            {
                                if ( RTqsize < maxwaiting && (i == lastbundle || i == coin->closestbundle || numwaiting < maxwaiting || numactive <= coin->MAXBUNDLES) )
                                {
                                    char str[65];
                                    bits256_str(str,hash2);
                                    if ( (rand() % 1000) == 0 && bp->issued[bundlei] > SMALLVAL )
                                        printf("issue.%d:%d of %d %s lag %f ave %f\n",bp->hdrsi,bundlei,bp->n,str,milliseconds() - bp->issued[bundlei],bp->avetime);
                                    bp->issued[bundlei] = milliseconds();
                                    n++;
                                    flag += (iguana_blockQ(coin,bp,bundlei,hash2,0) > 0);
                                }
                            }
                        }
                    } //lse printf("skip.%d %s\n",numbundles,bits256_str(hash2));
                }
            } else m = coin->chain->bundlesize;
        }
        prevbp = bp;
        if ( dispflag != 0 && bp != 0 && bp->emitfinish == 0 && m > 0 )
            printf("%s",iguana_bundledisp(coin,prevbp,bp,nextbp,m));
    }
    //if ( closestbundle >= 0 && (coin->closestbundle < 0 || coin->bundles[coin->closestbundle]->numrecv >= coin->chain->bundlesize) )
    coin->closestbundle = closestbundle;
    char str[65];
    if ( dispflag != 0 )
        printf(" PENDINGBUNDLES lastbundle.%d closest.[%d] %s | %d\n",lastbundle,closestbundle,mbstr(str,closest),coin->closestbundle);
    return(flag);
}

int32_t iguana_reqhdrs(struct iguana_info *coin)
{
    int32_t i,n = 0; struct iguana_bundle *bp; char hashstr[65];
    //printf("needhdrs.%d qsize.%d zcount.%d\n",iguana_needhdrs(coin),queue_size(&coin->hdrsQ),coin->zcount);
    if ( iguana_needhdrs(coin) > 0 && queue_size(&coin->hdrsQ) == 0 )
    {
        if ( coin->zcount++ > 10 )
        {
            for (i=0; i<coin->bundlescount; i++)
            {
                if ( (bp= coin->bundles[i]) != 0 )
                {
                    if ( time(NULL) > bp->issuetime+7 )//&& coin->numpendings < coin->MAXBUNDLES )
                    {
                        if ( bp->issuetime == 0 )
                            coin->numpendings++;
                        if ( bp->blockhashes == 0 || bp->n < coin->chain->bundlesize )
                        {
                            char str[65];
                            bits256_str(str,bp->bundlehash2);
                            printf("(%s %d).%d ",str,bp->bundleheight,i);
                            init_hexbytes_noT(hashstr,bp->bundlehash2.bytes,sizeof(bits256));
                            queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(hashstr),1);
                            n++;
                        }
                        bp->issuetime = (uint32_t)time(NULL);
                    }
                }
            }
            if ( n > 0 )
                printf("REQ HDRS pending.%d\n",coin->numpendings);
            coin->zcount = 0;
        }
    } else coin->zcount = 0;
    return(n);
}

void iguana_bundlestats(struct iguana_info *coin,char *str)
{
    int32_t i,j,bundlei,numbundles,numdone,numrecv,numhashes,numissued,numemit,numactive,flag;
    struct iguana_bundle *bp; bits256 hash2; int64_t estsize = 0;
    numbundles = numdone = numrecv = numhashes = numissued = numemit = numactive = 0;
    for (i=0; i<coin->bundlescount; i++)
    {
        if ( (bp= coin->bundles[i]) != 0 )
        {
            if ( bp->emitfinish != 0 )
                numemit++, numbundles++, numdone++, numhashes += (bp->n + 1), numissued += (bp->n + 1), numrecv += (bp->n + 1);
            else if ( bp->blockhashes != 0 )
            {
                numbundles++;
                if ( bp->numrecv > bp->n || bp->emitfinish != 0 )
                    numdone++, numhashes += (bp->n + 1), numissued += (bp->n + 1), numrecv += (bp->n + 1);
                else
                {
                    flag = 0;
                    for (j=0; j<bp->n&&j<coin->chain->bundlesize; j++)
                    {
                        bundlei = j;
                        hash2 = iguana_bundleihash2(coin,bp,bundlei);
                        if ( bits256_nonz(hash2) > 0 )
                        {
                            numhashes++;
                            if ( bp->issued[bundlei] > SMALLVAL )
                            {
                                numissued++;
                                if ( GETBIT(bp->recv,bundlei) != 0 )
                                {
                                    flag++;
                                    numrecv++;
                                }
                            }
                        }
                    }
                    if ( flag > 3 )
                    {
                        estsize += bp->estsize;
                        numactive++;
                    }
                }
            }
        }
    }
    char str2[65];
    sprintf(str,"N[%d] d.%d p.%d g.%d A.%d h.%d i.%d r.%d E.%d:%d long.%d est.%d %s",coin->bundlescount,numdone,coin->numpendings,numbundles,numactive,numhashes,numissued,numrecv,numemit,coin->numemitted,coin->longestchain,coin->MAXBUNDLES,mbstr(str2,estsize));
    coin->activebundles = numactive;
    coin->estsize = estsize;
}

int32_t iguana_updatecounts(struct iguana_info *coin)
{
    int32_t h,flag = 0;
    //SETBIT(coin->havehash,0);
    //while ( iguana_havetxdata(coin,coin->blocks.recvblocks) != 0 )
    //    coin->blocks.recvblocks++;
    //if ( coin->blocks.recvblocks < 1 )
    //    coin->blocks.recvblocks = 1;
    //while ( GETBIT(coin->havehash,coin->blocks.hashblocks) > 0 )
    //    coin->blocks.hashblocks++;
    h = coin->blocks.hwmheight - coin->chain->bundlesize;
    flag = 0;
    while ( 0 && iguana_bundleready(coin,h) > 0 )
    {
        h += coin->chain->bundlesize;
        flag++;
    }
    if ( flag != 0 )
        iguana_savehdrs(coin);
    return(flag);
}

int32_t iguana_processbundlesQ(struct iguana_info *coin,int32_t *newhwmp) // single threaded
{
    int32_t flag = 0; struct iguana_bundlereq *req;
    *newhwmp = 0;
    while ( flag < 10000 && (req= queue_dequeue(&coin->bundlesQ,0)) != 0 )
    {
        //printf("%s bundlesQ.%p type.%c n.%d\n",req->addr != 0 ? req->addr->ipaddr : "0",req,req->type,req->n);
        if ( req->type == 'B' ) // one block with all txdata
            req = iguana_recvblock(coin,req->addr,req,&req->block,req->numtx,req->datalen,newhwmp);
        else if ( req->type == 'H' ) // blockhdrs (doesnt have txn_count!)
        {
            if ( (req= iguana_recvblockhdrs(coin,req,req->blocks,req->n,newhwmp)) != 0 )
                myfree(req->blocks,sizeof(*req->blocks) * req->n), req->blocks = 0;
        }
        else if ( req->type == 'S' ) // blockhashes
        {
            if ( (req= iguana_recvblockhashes(coin,req,req->hashes,req->n)) != 0 && req->hashes != 0 )
                myfree(req->hashes,sizeof(*req->hashes) * req->n), req->hashes = 0;
        }
        else if ( req->type == 'U' ) // unconfirmed tx
            req = iguana_recvunconfirmed(coin,req,req->serialized,req->datalen);
        else if ( req->type == 'T' ) // txids from inv
        {
            if ( (req= iguana_recvtxids(coin,req,req->hashes,req->n)) != 0 )
                myfree(req->hashes,(req->n+1) * sizeof(*req->hashes)), req->hashes = 0;
        }
        else printf("iguana_updatebundles unknown type.%c\n",req->type);
        flag++;
        if ( req != 0 )
            myfree(req,req->allocsize), req = 0;
    }
    return(flag);
}

int32_t iguana_processrecv(struct iguana_info *coin) // single threaded
{
    int32_t newhwm = 0,flag = 0;
    //printf("process bundlesQ\n");
    flag += iguana_processbundlesQ(coin,&newhwm);
    //printf("iguana_updatecounts\n");
    flag += iguana_updatecounts(coin);
    //printf("iguana_reqhdrs\n");
    flag += iguana_reqhdrs(coin);
    //printf("iguana_issueloop\n");
    flag += iguana_issueloop(coin);
    //if ( newhwm != 0 )
    //    flag += iguana_lookahead(coin,&hash2,coin->blocks.hwmheight);
    return(flag);
}


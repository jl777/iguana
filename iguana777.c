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

void *iguana_kviAddriterator(struct iguana_info *coin,struct iguanakv *kv,struct iguana_kvitem *item,uint64_t args,void *key,void *value,int32_t valuesize)
{
    char ipaddr[64]; int32_t i; FILE *fp = (FILE *)args; struct iguana_peer *addr; struct iguana_iAddr *iA = value;
    if ( fp != 0 && iA != 0 && iA->numconnects > 0 && iA->lastconnect > time(NULL)-IGUANA_RECENTPEER )
    {
        for (i=0; i<coin->peers.numranked; i++)
            if ( (addr= coin->peers.ranked[i]) != 0 && addr->ipbits == iA->ipbits )
                break;
        if ( i == coin->peers.numranked )
        {
            expand_ipbits(ipaddr,iA->ipbits);
            fprintf(fp,"%s\n",ipaddr);
        }
    }
    return(0);
}

uint32_t iguana_updatemetrics(struct iguana_info *coin)
{
    char fname[512],tmpfname[512],oldfname[512]; int32_t i; struct iguana_peer *addr; FILE *fp;
    iguana_peermetrics(coin);
    sprintf(fname,"%s_peers.txt",coin->symbol);
    sprintf(oldfname,"%s_oldpeers.txt",coin->symbol);
    sprintf(tmpfname,"tmp/%s/peers.txt",coin->symbol);
    if ( (fp= fopen(tmpfname,"w")) != 0 )
    {
        for (i=0; i<coin->peers.numranked; i++)
            if ( (addr= coin->peers.ranked[i]) != 0 )
                fprintf(fp,"%s\n",addr->ipaddr);
        portable_mutex_lock(&coin->peers_mutex);
        iguana_kviterate(coin,coin->iAddrs,(uint64_t)(long)fp,iguana_kviAddriterator);
        portable_mutex_unlock(&coin->peers_mutex);
        if ( ftell(fp) > iguana_filesize(fname) )
        {
            printf("new peers.txt %ld vs (%s) %ld\n",ftell(fp),fname,(long)iguana_filesize(fname));
            fclose(fp);
            iguana_renamefile(fname,oldfname);
            iguana_copyfile(tmpfname,fname,1);
        } else fclose(fp);
    }
    return((uint32_t)time(NULL));
}

void iguana_recvalloc(struct iguana_info *coin,int32_t numitems)
{
    //int32_t numbundles;
    coin->R.waitingbits = myrealloc('W',coin->R.waitingbits,coin->R.waitingbits==0?0:coin->R.numwaitingbits/8+1,numitems/8+1);
    //coin->R.recvblocks = myrealloc('W',coin->R.recvblocks,coin->R.recvblocks==0?0:coin->R.numwaitingbits * sizeof(*coin->R.recvblocks),numitems * sizeof(*coin->R.recvblocks));
    coin->R.waitstart = myrealloc('W',coin->R.waitstart,coin->R.waitstart==0?0:coin->R.numwaitingbits * sizeof(*coin->R.waitstart),numitems * sizeof(*coin->R.waitstart));
    coin->blocks.ptrs = myrealloc('W',coin->blocks.ptrs,coin->blocks.ptrs==0?0:coin->R.numwaitingbits * sizeof(*coin->blocks.ptrs),numitems * sizeof(*coin->blocks.ptrs));
    //numbundles = (numitems / coin->chain->bundlesize) + 1;
    //coin->R.bundles = myrealloc('h',coin->R.bundles,coin->R.bundles==0?0:coin->R.numbundles * sizeof(*coin->R.bundles),numbundles * sizeof(*coin->R.bundles));
    //coin->R.numbundles = numbundles;
    printf("realloc waitingbits.%d -> %d\n",coin->R.numwaitingbits,numitems);
    coin->R.numwaitingbits = numitems;
}

/*uint32_t iguana_issuereqs(struct iguana_info *coin)
{
    int32_t width,w;
    coin->width = width = 4*sqrt(coin->longestchain - coin->blocks.recvblocks);
    if ( coin->width < 0 )
        width = 500;
    coin->widthready = 0;
    coin->width = 5000;
    //printf("width.%d\n",width);
    while ( iguana_recvblock(coin,coin->blocks.recvblocks) != 0 )
    {
        coin->blocks.recvblocks++;
        //printf("RECV.%d\n",coin->blocks.recvblocks);
    }
    while ( width < (coin->longestchain - coin->blocks.recvblocks) )
    {
        w = iguana_updatewaiting(coin,coin->blocks.recvblocks,width);
        //printf("w%d ",w);
        if ( width == coin->width )
            coin->widthready = w;
        //else
            break;
        width <<= 1;
        if ( width >= coin->longestchain-coin->blocks.recvblocks )
            width = coin->longestchain-coin->blocks.recvblocks-1;
        if ( (rand() % 100) == 0 && width > (coin->width<<2) )
            printf("coin->width.%d higher width.%d all there, w.%d\n",coin->width,width,w);
    }
    return((uint32_t)time(NULL));
}*/

void iguana_helper(void *arg)
{
    int32_t flag,i,n; struct iguana_bundle *bundle; struct iguana_info *coin,**coins = arg;
    n = (int32_t)(long)coins[0];
    coins++;
    printf("start helper\n");
    while ( 1 )
    {
        flag = 0;
        for (i=0; i<n; i++)
        {
            if ( (coin= coins[i]) != 0 && coin->firstblock != 0 )
            {
                if ( (bundle= queue_dequeue(&coin->emitQ,0)) != 0 )
                {
                    printf("START emittxdata.%d\n",bundle->height);
                    iguana_emittxdata(coin,bundle), flag++;
                    printf("FINISH emittxdata.%d\n",bundle->height);
                }
            }
        }
        if ( flag == 0 )
            usleep(1000000);
    }
}

void iguana_coinloop(void *arg)
{
    int32_t flag,i,n,m; uint32_t now,lastdisp = 0; struct iguana_info *coin,**coins = arg;
    n = (int32_t)(long)coins[0];
    for (i=0; i<IGUANA_NUMHELPERS; i++)
        iguana_launch("helpers",iguana_helper,coins,IGUANA_HELPERTHREAD);
    coins++;
    printf("begin coinloop[%d]\n",n);
    coin = coins[0];
    iguana_possible_peer(coin,"127.0.0.1");
    while ( 1 )
    {
        flag = 0;
        for (i=0; i<n; i++)
        {
            if ( (coin= coins[i]) != 0 )
            {
                now = (uint32_t)time(NULL);
                if ( now > coin->lastpossible )
                    coin->lastpossible = iguana_possible_peer(coin,0); // tries to connect to new peers
                if ( now > coin->peers.lastmetrics+60 )
                    coin->peers.lastmetrics = iguana_updatemetrics(coin); // ranks peers
                {
                    portable_mutex_lock(&coin->bundles_mutex);
                        if ( coin->R.numwaitingbits < coin->longestchain+100000 ) // assumes < 100Kblocks/iter
                            iguana_recvalloc(coin,coin->longestchain + 200000);
                        //iguana_updatehdrs(coin); // creates block headers directly or from blockhashes
                    portable_mutex_unlock(&coin->bundles_mutex);
                }
                flag += iguana_updatebundles(coin);
                //if ( now > coin->lastwaiting )
                //    coin->lastwaiting = iguana_issuereqs(coin); // updates waiting Q's and issues reqs
                if ( 0 && coin->blocks.parsedblocks < coin->blocks.hwmheight-coin->chain->minconfirms )
                {
                        if ( iguana_updateramchain(coin) != 0 )
                            iguana_syncs(coin), flag++; // merge ramchain fragments into full ramchain
                        flag += iguana_processjsonQ(coin);
                }
            }
        }
        if ( now > lastdisp+1 )
        {
            lastdisp = (uint32_t)now;
            for (i=m=0; i<coin->longestchain; i++)
                if ( iguana_havehash(coin,i) > 0 )
                    m++;
            printf("%s.%d: pend.%d/%d hash.%d/%d I.%d recv.%d/%d emit.%d HWM.%d parsed.%d |long.%d %.2f min\n",coin->symbol,flag,coin->numpendings,coin->hdrscount,coin->blocks.hashblocks,m,coin->blocks.issuedblocks,coin->blocks.recvblocks,coin->recvcount,coin->blocks.emitblocks,coin->blocks.hwmheight,coin->blocks.parsedblocks,coin->longestchain,(double)(time(NULL)-coin->starttime)/60.);
        }
        if ( flag == 0 )
            usleep(5000);
    }
}

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

// threadsafe
int32_t iguana_peerfname(struct iguana_info *coin,char *fname,uint32_t ipbits,bits256 hash2)
{
    struct iguana_bundle *bp = 0; int32_t bundlei; char str[65];
    if ( ipbits == 0 )
        printf("illegal ipbits.%d\n",ipbits), getchar();
    if ( (bp= iguana_bundlefind(coin,&bp,&bundlei,hash2)) != 0 )
        hash2 = bp->hashes[0];
    sprintf(fname,"tmp/%s/%s.peer%08x",coin->symbol,bits256_str(str,hash2),ipbits);
    return(bundlei);
}

int32_t iguana_peerfile_exists(struct iguana_info *coin,struct iguana_peer *addr,char *fname,bits256 hash2)
{
    FILE *fp; int32_t bundlei;
    if ( (bundlei= iguana_peerfname(coin,fname,addr->ipbits,hash2)) >= 0 )
    {
        if ( (fp= fopen(fname,"rb")) == 0 )
            bundlei = -1;
        else fclose(fp);
    }
    return(bundlei);
}

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
            //if ( memcmp(block->hash2.bytes,coin->chain->genesis_hashdata,sizeof(bits256)) == 0 )
            //    ptrs[i] = (struct iguana_txblock *)coin->chain->genesis_hashdata, flag++;
            //else
            {
                iguana_meminit(&memB[i],"ramchainB",0,block->recvlen + 4096,0);
                if ( (ptr= iguana_peertxdata(coin,&bundlei,fname,&memB[i],block->ipbits,block->hash2)) != 0 )
                {
                    if ( bundlei != i || ptr->block.bundlei != i )
                        printf("peertxdata.%d bundlei.%d, i.%d block->bundlei.%d\n",bp->ramchain.hdrsi,bundlei,i,ptr->block.bundlei);
                    ptrs[i] = &ramchains[i];
                    if ( iguana_ramchainset(coin,ptrs[i],ptr) == ptrs[i] )
                    {
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
    }
    if ( flag == i )
    {
        printf(">>>>>>>>> start MERGE.(%ld) i.%d flag.%d estimated.%ld maxrecv.%d\n",(long)mem->totalsize,i,flag,(long)estimatedsize,maxrecv);
        if ( (ramchain= iguana_ramchainmergeHT(coin,mem,ptrs,i,bp)) != 0 )
        {
            iguana_ramchainsave(coin,ramchain);
            iguana_ramchainfree(coin,mem,ramchain);
            printf("ramchain saved\n");
            bp->emitfinish = (uint32_t)time(NULL);
        } else bp->emitfinish = 0;
        for (addrind=0; addrind<IGUANA_MAXPEERS; addrind++)
        {
            if ( coin->peers.active[addrind].ipbits != 0 )
            {
                if ( iguana_peerfile_exists(coin,&coin->peers.active[addrind],fname,bp->hashes[0]) >= 0 )
                {
                    //printf("remove.(%s)\n",fname);
                    //iguana_removefile(fname,0);
                    coin->peers.numfiles--;
                }
            }
        }
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
        printf("emitQ coin.%p bp.%p\n",ptr->coin,ptr->bp);
        if ( (coin= ptr->coin) != 0 )
        {
            if ( (bp= ptr->bp) != 0 )
            {
                bp->emitfinish = (uint32_t)time(NULL);
                if ( iguana_bundlesaveHT(coin,mem,memB,bp) == 0 )
                    coin->numemitted++;
            }
            printf("MAXBUNDLES.%d vs max.%d estsize %ld vs cache.%ld\n",coin->MAXBUNDLES,_IGUANA_MAXBUNDLES,(long)coin->estsize,(long)coin->MAXRECVCACHE);
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



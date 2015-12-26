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

void iguana_initQ(queue_t *Q,char *name)
{
    char *tst,*str = "need to init each Q when single threaded";
    queue_enqueue(name,Q,queueitem(str),1);
    if ( (tst= queue_dequeue(Q,1)) != 0 )
        free_queueitem(tst);
}

void iguana_initQs(struct iguana_info *coin)
{
    int32_t i;
    iguana_initQ(&coin->bundlesQ,"bundlesQ");
    iguana_initQ(&coin->hdrsQ,"hdrsQ");
    iguana_initQ(&coin->blocksQ,"blocksQ");
    iguana_initQ(&coin->priorityQ,"priorityQ");
    iguana_initQ(&coin->possibleQ,"possibleQ");
    iguana_initQ(&coin->jsonQ,"jsonQ");
    iguana_initQ(&coin->finishedQ,"finishedQ");
    //iguana_initQ(&coin->helperQ,"helperQ");
    iguana_initQ(&coin->TerminateQ,"TerminateQ");
    for (i=0; i<IGUANA_MAXPEERS; i++)
        iguana_initQ(&coin->peers.active[i].sendQ,"addrsendQ");
}

void iguana_initpeer(struct iguana_info *coin,struct iguana_peer *addr,uint32_t ipbits)
{
    memset(addr,0,sizeof(*addr));
    addr->ipbits = ipbits;
    addr->usock = -1;
    expand_ipbits(addr->ipaddr,addr->ipbits);
    //addr->pending = (uint32_t)time(NULL);
    strcpy(addr->symbol,coin->symbol);
    strcpy(addr->coinstr,coin->name);
    iguana_initQ(&addr->sendQ,"addrsendQ");
}

void iguana_initcoin(struct iguana_info *coin)
{
    int32_t i;
    portable_mutex_init(&coin->peers_mutex);
    portable_mutex_init(&coin->blocks_mutex);
    iguana_meminit(&coin->blockMEM,"blockMEM",coin->blockspace,sizeof(coin->blockspace),0);
    iguana_initQs(coin);
    randombytes((unsigned char *)&coin->instance_nonce,sizeof(coin->instance_nonce));
    coin->starttime = (uint32_t)time(NULL);
    coin->avetime = 1 * 1000;
    //coin->R.maxrecvbundles = IGUANA_INITIALBUNDLES;
    for (i=0; i<IGUANA_MAXPEERS; i++)
        coin->peers.active[i].usock = -1;
    for (i=0; i<IGUANA_NUMAPPENDS; i++)
        vupdate_sha256(coin->latest.lhashes[i].bytes,&coin->latest.states[i],0,0);
}

bits256 iguana_genesis(struct iguana_info *coin,struct iguana_chain *chain)
{
    struct iguana_block block,*ptr; struct iguana_msgblock msg; bits256 hash2; char str[65]; uint8_t buf[1024]; int32_t height;
    decode_hex(buf,(int32_t)strlen(chain->genesis_hex)/2,(char *)chain->genesis_hex);
    hash2 = bits256_doublesha256(0,buf,sizeof(struct iguana_msgblockhdr));
    iguana_rwblock(0,&hash2,buf,&msg);
    if  ( memcmp(hash2.bytes,chain->genesis_hashdata,sizeof(hash2)) != 0 )
    {
        bits256_str(str,hash2);
        printf("genesis mismatch? calculated %s vs %s\n",str,(char *)chain->genesis_hex);
        memset(hash2.bytes,0,sizeof(hash2));
        return(hash2);
    }
    bits256_str(str,hash2);
    printf("genesis.(%s) len.%d hash.%s\n",chain->genesis_hex,(int32_t)sizeof(msg.H),str);
    iguana_blockconv(&block,&msg,hash2,0);
    //coin->latest.dep.numtxids =
    block.numvouts = 1;
    iguana_gotdata(coin,0,0);
    if ( (ptr= iguana_blockhashset(coin,0,hash2,1)) != 0 )
    {
        iguana_blockcopy(coin,ptr,&block);
        if ( (height= iguana_chainextend(coin,ptr)) == 0 )
        {
            block = *ptr;
            coin->blocks.recvblocks = coin->blocks.issuedblocks = 1;
        }
        else printf("genesis block doesnt validate for %s ht.%d\n",coin->symbol,height);
    } else printf("couldnt hashset genesis\n");
    if ( coin->blocks.hwmchain.height != 0 || fabs(coin->blocks.hwmchain.PoW - block.PoW) > SMALLVAL || memcmp(coin->blocks.hwmchain.hash2.bytes,hash2.bytes,sizeof(hash2)) != 0 )
    {
        printf("%s genesis values mismatch hwmheight.%d %.15f %.15f %s\n",coin->name,coin->blocks.hwmchain.height,coin->blocks.hwmchain.PoW,block.PoW,bits256_str(str,coin->blocks.hwmchain.hash2));
        exit(-1);
    }
    return(hash2);
}

int32_t iguana_savehdrs(struct iguana_info *coin)
{
    int32_t height,iter,retval = 0; char fname[512],tmpfname[512],oldfname[512]; bits256 hash2; FILE *fp;
    sprintf(oldfname,"%s_oldhdrs.txt",coin->symbol);
    sprintf(tmpfname,"tmp/%s/hdrs.txt",coin->symbol);
    sprintf(fname,"%s_hdrs.txt",coin->symbol);
    if ( (fp= fopen(tmpfname,"w")) != 0 )
    {
        fprintf(fp,"%d\n",coin->blocks.hashblocks);
        for (height=0; height<=coin->blocks.hwmchain.height; height+=coin->chain->bundlesize)
        {
            for (iter=0; iter<2; iter++)
            {
                hash2 = iguana_blockhash(coin,height+iter);
                if ( bits256_nonz(hash2) > 0 )
                {
                    char str[65];
                    bits256_str(str,hash2);
                    fprintf(fp,"%d %s\n",height+iter,str);
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
    int32_t j,k,m,c,height,flag,bundlei,bundleheight = -1; char checkstr[1024],line[1024]; bits256 zero;
    struct iguana_peer *addr; struct iguana_bundle *bp; bits256 hash2,bundlehash2;
    m = flag = 0;
    memset(&zero,0,sizeof(zero));
    while ( fgets(line,sizeof(line),fp) > 0 )
    {
        j = (int32_t)strlen(line) - 1;
        line[j] = 0;
        //printf("parse line.(%s) maxpeers.%d\n",line,coin->MAXPEERS);
        if ( iter == 0 )
        {
            if ( m < coin->MAXPEERS && m < 32 )
            {
                addr = &coin->peers.active[m++];
                iguana_initpeer(coin,addr,(uint32_t)calc_ipbits(line));
                printf("call initpeer.(%s)\n",addr->ipaddr);
                iguana_launch(coin,"connection",iguana_startconnection,addr,IGUANA_CONNTHREAD);
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
            printf("parseline: k.%d %d height.%d m.%d bundlesize.%d\n",k,line[k],height,m,coin->chain->bundlesize);
            if ( line[k] == ' ' )
            {
                decode_hex(hash2.bytes,sizeof(hash2),line+k+1);
                init_hexbytes_noT(checkstr,hash2.bytes,sizeof(hash2));
                if ( strcmp(checkstr,line+k+1) == 0 )
                {
                    if ( (height % coin->chain->bundlesize) == 0 )
                    {
                        if ( height > coin->blocks.maxbits-coin->chain->bundlesize*10 )
                            iguana_recvalloc(coin,height + coin->chain->bundlesize*100);
                        if ( flag != 0 )
                        {
                            if ( (bp= iguana_bundlecreate(coin,&bundlei,height,bundlehash2)) != 0 )
                            {
                                char str[65];
                                bits256_str(str,bundlehash2);
                                printf("add bundle.%d:%d (%s) %p\n",bundleheight,bp->hdrsi,str,bp);
                                bp->bundleheight = bundleheight;
                                flag = 0;
                            }
                        }
                        bundlehash2 = hash2;
                        bundleheight = height;
                        flag = 1;
                    }
                    else if ( (height % coin->chain->bundlesize) == 1 && height == bundleheight+1 )
                    {
                        if ( (bp= iguana_bundlecreate(coin,&bundlei,height-1,bundlehash2)) != 0 )
                        {
                            if ( iguana_bundlehash2add(coin,0,bp,1,hash2) == 0 )
                            {
                                char str[65],str2[65];
                                bits256_str(str,bundlehash2);
                                bits256_str(str2,hash2);
                                printf("add bundle.%d:%d (%s) %s %p\n",bundleheight,bp->hdrsi,str,str2,bp);
                                flag = 0;
                            }
                        }
                    }
                    iguana_blockhashset(coin,height,hash2,100);
                }
            }
        }
    }
}

struct iguana_info *iguana_startcoin(struct iguana_info *coin,int32_t initialheight,int32_t mapflags)
{
    FILE *fp; char fname[512],*symbol; int32_t iter;
    coin->sleeptime = 10000;
    symbol = coin->symbol;
    if ( initialheight < coin->chain->bundlesize*10 )
        initialheight = coin->chain->bundlesize*10;
    iguana_recvalloc(coin,initialheight);
    coin->longestchain = 1;
    coin->blocks.hwmchain.height = 0;
    /*if ( 0 )
    {
        coin->blocks.db = iguana_stateinit(coin,IGUANA_ITEMIND_DATA|((mapflags&IGUANA_MAPBLOCKITEMS)!=0)*IGUANA_MAPPED_ITEM,symbol,symbol,"blocks",(int32_t)((long)&space.hash2 - (long)&space),sizeof(bits256),sizeof(struct iguana_block)-sizeof(bits256),sizeof(struct iguana_block),10000,iguana_verifyblock,iguana_initblock,0,0,0,initialheight,1);
        printf("coin->blocks.hwmheight.%d longest.%d coin->numiAddrs.%d\n",coin->blocks.hwmheight,coin->longestchain,coin->numiAddrs);
        if ( (height= iguana_initramchain(coin,coin->blocks.hwmheight,mapflags,1)) < 0 )
        {
            printf("iguana_startcoin: unrecoverable failure in truncating ramchain table.%x\n",-height);
            exit(1);
        }
        //iguana_audit(coin);
        iguana_syncs(coin);
    }*/
    coin->firstblock = coin->blocks.parsedblocks + 1;
    for (iter=0; iter<2; iter++)
    {
        sprintf(fname,"%s_%s.txt",coin->symbol,(iter == 0) ? "peers" : "hdrs");
        printf("parsefile.%d %s\n",iter,fname);
        if ( (fp= fopen(fname,"r")) != 0 )
        {
            iguana_parseline(coin,iter,fp);
            fclose(fp);
        }
        printf("done parsefile.%d\n",iter);
    }
#ifndef IGUANA_DEDICATED_THREADS
    coin->peers.peersloop = iguana_launch("peersloop",iguana_peersloop,coin,IGUANA_PERMTHREAD);
#endif
    if ( 0 && (coin->MAXBUNDLES= coin->bundlescount / 4) < _IGUANA_MAXBUNDLES )
        coin->MAXBUNDLES = _IGUANA_MAXBUNDLES;
    //coin->peers.acceptloop = iguana_launch("acceptloop",iguana_acceptloop,coin,IGUANA_PERMTHREAD);
    //coin->peers.recvloop = iguana_launch("recvloop",iguana_recvloop,coin,IGUANA_PERMTHREAD);
    iguana_genesis(coin,coin->chain);
    printf("started.%s\n",coin->symbol);
    return(coin);
}

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

void iguana_initcoin(struct iguana_info *coin)
{
    int32_t i;
    portable_mutex_init(&coin->peers_mutex);
    portable_mutex_init(&coin->blocks_mutex);
    portable_mutex_init(&coin->peers.filesM_mutex);
    iguana_initQs(coin);
    randombytes((unsigned char *)&coin->instance_nonce,sizeof(coin->instance_nonce));
    coin->starttime = (uint32_t)time(NULL);
    coin->avetime = 1 * 1000;
    //coin->R.maxrecvbundles = IGUANA_INITIALBUNDLES;
    for (i=0; i<IGUANA_NUMAPPENDS; i++)
        vupdate_sha256(coin->latest.lhashes[i].bytes,&coin->latest.states[i],0,0);
}

bits256 iguana_genesis(struct iguana_info *coin,struct iguana_chain *chain)
{
    struct iguana_block block,*ptr; struct iguana_msgblock msg; bits256 hash2;
    char str[65]; uint8_t buf[1024]; struct iguana_prevdep L;
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
    memset(&L,0,sizeof(L));
    L.numtxids = L.numunspents = L.numspends = L.numpkinds = 1;
    L.PoW = PoW_from_compact(msg.H.bits,coin->chain->unitval);
    bits256_str(str,hash2);
    printf("genesis.(%s) len.%d hash.%s\n",chain->genesis_hex,(int32_t)sizeof(msg.H),str);
    iguana_convblock(&block,&msg,hash2,0);
    coin->latest.dep.numtxids = block.numvouts = 1;
    iguana_gotdata(coin,0,0,hash2);
    if ( (ptr= iguana_blockhashset(coin,0,hash2,100)) != 0 )
        ptr->mainchain = 1, ptr->height = 0, coin->blocks.recvblocks = coin->blocks.issuedblocks = 1;
    iguana_chainextend(coin,hash2,&block,&L);
    if ( coin->blocks.hwmheight != 0 || fabs(coin->blocks.hwmPoW - L.PoW) > SMALLVAL || memcmp(coin->blocks.hwmchain.bytes,hash2.bytes,sizeof(hash2)) != 0 )
    {
        printf("%s genesis values mismatch\n",coin->name);
        exit(-1);
    }
    return(hash2);
}

int32_t iguana_savehdrs(struct iguana_info *coin)
{
    int32_t height,iter,valid,retval = 0; char fname[512],tmpfname[512],oldfname[512]; bits256 hash2; FILE *fp;
    sprintf(oldfname,"%s_oldhdrs.txt",coin->symbol);
    sprintf(tmpfname,"tmp/%s/hdrs.txt",coin->symbol);
    sprintf(fname,"%s_hdrs.txt",coin->symbol);
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
    int32_t j,k,m,c,height,flag,bundleheight = -1; char checkstr[1024],line[1024]; bits256 zero;
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
                            if ( (bp= iguana_bundlecreate(coin,bundlehash2,zero)) != 0 )
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
                        if ( (bp= iguana_bundlecreate(coin,bundlehash2,hash2)) != 0 )
                        {
                            char str[65],str2[65];
                            bits256_str(str,bundlehash2);
                            bits256_str(str2,hash2);
                            printf("add bundle.%d:%d (%s) %s %p\n",bundleheight,bp->hdrsi,str,str2,bp);
                            bp->bundleheight = bundleheight;
                            flag = 0;
                        }
                    }
                    iguana_blockhashset(coin,height,hash2,100);
                }
            }
        }
    }
}

int32_t iguana_verifyiAddr(struct iguana_info *coin,void *key,void *value,int32_t itemind,int32_t itemsize)
{
    struct iguana_iAddr *iA = value;
    if ( itemind == 0 || iA->ipbits != 0 )
        return(0);
    else return(-1);
}

int32_t iguana_initiAddr(struct iguana_info *coin,struct iguanakv *kv,void *key,void *value,int32_t itemind,int32_t itemsize,int32_t numitems)
{
    struct iguana_iAddr *iA = value;
    if ( key == 0 && value == 0 && itemind < 0 && numitems == 0 )
    {
    }
    else
    {
        if ( iA != 0 )
            iA->status = 0;
        coin->numiAddrs++;
        //printf("%x numiAddrs.%d\n",iA->ipbits,coin->numiAddrs);
    }
    return(0);
}

int32_t iguana_verifyblock(struct iguana_info *coin,void *key,void *value,int32_t itemind,int32_t itemsize)
{
    struct iguana_block *block;
    block = value;
    if ( bits256_nonz(block->hash2) != 0 )
        return(0);
    else return(-1);
}

int32_t iguana_initblock(struct iguana_info *coin,struct iguanakv *kv,void *key,void *value,int32_t itemind,int32_t itemsize,int32_t numitems)
{
    bits256 genesis; //struct iguana_block *block = value;
    if ( key == 0 && value == 0 && itemind < 0 && numitems == 0 )
    {
        if ( coin->blocks.db == 0 )
            coin->blocks.db = kv;
        genesis = iguana_genesis(coin,coin->chain);
        if ( bits256_nonz(genesis) == 0 )
            return(-1);
        else return(0);
    }
    return(0);
}

int32_t iguana_nullinit(struct iguana_info *coin,struct iguanakv *kv,void *key,void *value,int32_t itemind,int32_t itemsize,int32_t numitems)
{
    if ( key != 0 && value != 0 && itemind > 0 )
    {
    }
    return(0);
}

int32_t iguana_verifyunspent(struct iguana_info *coin,void *key,void *value,int32_t itemind,int32_t itemsize)
{
    if ( itemind < coin->latest.dep.numunspents )
        return(0);
    else return(-1);
}

int32_t iguana_verifyspend(struct iguana_info *coin,void *key,void *value,int32_t itemind,int32_t itemsize)
{
    if ( itemind < coin->latest.dep.numspends )
        return(0);
    else return(-1);
}

int32_t iguana_verifytxid(struct iguana_info *coin,void *key,void *value,int32_t itemind,int32_t itemsize)
{
    if ( itemind < coin->latest.dep.numtxids )
        return(0);
    else return(-1);
}

int32_t iguana_inittxid(struct iguana_info *coin,struct iguanakv *kv,void *key,void *value,int32_t itemind,int32_t itemsize,int32_t numitems)
{
    //uint32_t checktxidind,firstvout,firstvin; struct iguana_txid *tx = value;
    if ( key != 0 && value != 0 && itemind > 0 )
    {
        /*printf("inittxid.(%s) itemind.%d (%d %d)\n",bits256_str(tx->txid),itemind,tx->firstvout,tx->firstvin);
        checktxidind = iguana_txidind(coin,&firstvout,&firstvin,tx->txid);
        if ( checktxidind != itemind )
        {
            printf("init checktxidind != itemind: %s -> %d vs %d\n",bits256_str(tx->txid),checktxidind,itemind);
            return(-1);
        }*/
    }
    return(0);
}

int32_t iguana_verifypkhash(struct iguana_info *coin,void *key,void *value,int32_t itemind,int32_t itemsize)
{
    if ( itemind < coin->latest.dep.numpkinds )
        return(0);
    else return(-1);
}

void iguana_initpeer(struct iguana_info *coin,struct iguana_peer *addr,uint32_t ipbits)
{
    memset(addr,0,sizeof(*addr));
    addr->ipbits = ipbits;
    addr->usock = -1;
    expand_ipbits(addr->ipaddr,addr->ipbits);
    addr->pending = (uint32_t)time(NULL);
    strcpy(addr->symbol,coin->symbol);
    strcpy(addr->coinstr,coin->name);
    iguana_initQ(&addr->sendQ,"addrsendQ");
}

struct iguanakv *iguana_kvinit(char *name,int32_t keysize,int32_t threadsafe,int32_t mapped_datasize,int32_t RAMvaluesize,int32_t keyoffset,int32_t flags,int32_t valuesize2,int32_t valuesize3)
{
    struct iguanakv *kv;
    printf("iguana_kvinit.(%s) keysize.%d mapped_datasize.%d keyoffset.%d\n",name,keysize,mapped_datasize,keyoffset);
    kv = mycalloc('K',1,sizeof(*kv));
    portable_mutex_init(&kv->MMlock);
    //portable_mutex_init(&kv->MEM.mutex);
    portable_mutex_init(&kv->HASHPTRS.mutex);
    portable_mutex_init(&kv->KVmutex);
    strcpy(kv->name,name);
    kv->flags = flags;
    kv->valuesize2 = valuesize2, kv->valuesize3 = valuesize3;
    kv->RAMvaluesize = RAMvaluesize;
    kv->HDDvaluesize = mapped_datasize;
    kv->keyoffset = keyoffset;
    kv->mult = IGUANA_ALLOC_MULT;
    kv->threadsafe = threadsafe;
    kv->keysize = keysize;
    return(kv);
}

int32_t iguana_loadkvfile(struct iguana_info *coin,struct iguanakv *kv,int32_t valuesize,int32_t (*verifyitem)(struct iguana_info *coin,void *key,void *ptr,int32_t itemind,int32_t itemsize),int32_t (*inititem)(struct iguana_info *coin,struct iguanakv *kv,void *key,void *ptr,int32_t itemind,int32_t itemsize,int32_t numitems),int32_t maxind)
{
    FILE *fp; long fpos; uint8_t *ptr; double lastdisp,factor; int32_t numitems=0,itemind,j,n,skip = 0;
    factor = 1.;
    if ( (fp= fopen(kv->fname,"rb")) != 0 )
    {
        fseek(fp,0,SEEK_END);
        fpos = ftell(fp);
        numitems = (int32_t)(fpos / valuesize);
        fclose(fp);
        if ( kv->RAMvaluesize > 0  && kv->HDDvaluesize > 0 && kv->RAMvaluesize > kv->HDDvaluesize && numitems > 0 )
            numitems--;
        iguana_kvensure(coin,kv,0);
        if ( numitems > 2 || maxind > 0 )
        {
            if ( maxind == 0 )
            {
                for (itemind=numitems-2; itemind>0; itemind--)
                {
                    ptr = (uint8_t *)((unsigned long)kv->M.fileptr + ((unsigned long)itemind * kv->HDDvaluesize));
                    if ( (*verifyitem)(coin,(void *)&ptr[kv->keyoffset],(void *)ptr,itemind,kv->RAMvaluesize) < 0 )
                    {
                        numitems = itemind + 1;
                        printf("numitems.%d\n",numitems);
                        break;
                    }
                }
            } else numitems = maxind;
            if ( numitems > 0 )
            {
                lastdisp = 0.;
                for (itemind=0; itemind<numitems; itemind++)
                {
                    if ( numitems > 1000000 && ((double)itemind / numitems) > lastdisp+.01*factor )
                    {
                        if ( factor == 1. )
                            fprintf(stderr,"%.0f%% ",100. * lastdisp);
                        else fprintf(stderr,"%.2f%% ",100. * lastdisp);
                        lastdisp = ((double)itemind / numitems);
                    }
                    ptr = (uint8_t *)((uint64_t)kv->M.fileptr + ((uint64_t)itemind * kv->HDDvaluesize));
                    if ( 0 && kv->keysize > 0 )
                    {
                        for (j=0; j<kv->keysize; j++)
                            if ( ptr[j] != 0 )
                                break;
                        if ( j != kv->keysize && iguana_kvread(coin,kv,(void *)&ptr[kv->keyoffset],kv->space,(uint32_t *)&n) != 0 )
                        {
                            printf("%s: skip duplicate %llx itemind.%d already at %d\n",kv->name,*(long long *)&ptr[kv->keyoffset],itemind,n);
                            continue;
                        }
                        //printf("%s uniq item at itemind.%d\n",kv->name,itemind);
                    }
                    if ( (*verifyitem)(coin,(void *)&ptr[kv->keyoffset],(void *)ptr,itemind,kv->RAMvaluesize) == 0 )
                    {
                        //if ( strcmp("txids",kv->name) == 0 )
                        //printf("inititem.%d %p (%s)\n",itemind,ptr,bits256_str(*(bits256 *)&ptr[kv->keyoffset]));
                        //    iguana_kvwrite(coin,kv,(void *)&ptr[kv->keyoffset],sp->space,(uint32_t *)&n);
                        if ( (*inititem)(coin,kv,(void *)&ptr[kv->keyoffset],(void *)ptr,itemind,kv->RAMvaluesize,numitems) == 0 )
                        {
                            kv->numvalid++;
                            n = itemind;
                            memcpy(kv->space,ptr,kv->RAMvaluesize);
                            if ( kv->keysize > 0 )
                                iguana_kvwrite(coin,kv,(void *)&ptr[kv->keyoffset],kv->space,(uint32_t *)&n);
                            else iguana_kvwrite(coin,kv,0,kv->space,(uint32_t *)&n);
                        } else skip++;
                    } else break;
                }
            }
        }
        kv->numitems = numitems;
        kv->numkeys = numitems;
        kv->maxitemind = (numitems > 0 ) ? numitems - 1 : 0;
        printf("%s: numkeys.%d numitems.%d numvalid.%d maxitemind.%d skipped.%d ELAPSED %.2f minutes\n",kv->name,kv->numkeys,kv->numitems,kv->numvalid,kv->maxitemind,skip,(double)(time(NULL)-coin->starttime)/60.);
        if ( (kv->flags & IGUANA_ITEMIND_DATA) != 0 )
            iguana_syncmap(&kv->M,0);
        /*if ( strcmp(kv->name,"iAddrs") == 0 && kv->numkeys < numitems/2 )
         {
         iguana_closemap(&kv->M);
         printf("truncate?\n"), getchar();
         truncate(kv->fname,(kv->numkeys+100)*kv->HDDvaluesize);
         }*/
    }
    return(numitems);
}

struct iguanakv *iguana_stateinit(struct iguana_info *coin,int32_t flags,char *coinstr,char *subdir,char *name,int32_t keyoffset,int32_t keysize,int32_t HDDvaluesize,int32_t RAMvaluesize,int32_t inititems,int32_t (*verifyitem)(struct iguana_info *coin,void *key,void *ptr,int32_t itemind,int32_t itemsize),int32_t (*inititem)(struct iguana_info *coin,struct iguanakv *kv,void *key,void *ptr,int32_t itemind,int32_t itemsize,int32_t numitems),int32_t valuesize2,int32_t valuesize3,int32_t maxind,int32_t initialnumitems,int32_t threadsafe)
{
    struct iguanakv *kv; int32_t valuesize;
    if ( maxind <= 1 )
        maxind = 0;
    printf("%s MAX.%d\n",name,maxind);
    if ( HDDvaluesize == 0 )
        valuesize = HDDvaluesize = RAMvaluesize;
    else valuesize = HDDvaluesize;
    kv = iguana_kvinit(name,keysize,threadsafe,HDDvaluesize,RAMvaluesize,keyoffset,flags,valuesize2,valuesize3);
    if ( kv == 0 )
    {
        printf("cant initialize kv.(%s)\n",name);
        exit(-1);
    }
    if ( (kv->incr= inititems) == 0 )
        kv->incr = IGUANA_ALLOC_INCR;
    strcpy(kv->name,name);
    sprintf(kv->fname,"DB/%s/%s",coin->symbol,kv->name), iguana_compatible_path(kv->fname);
    portable_mutex_init(&kv->MMmutex);
    kv->space = mycalloc('K',1,RAMvaluesize + kv->keysize);
    kv->maxitemind = kv->numvalid = kv->numitems = 0;
    if ( strcmp("txids",kv->name) == 0 )
        coin->txids = kv;
    else if ( strcmp("pkhashes",kv->name) == 0 )
        coin->pkhashes = kv;
    printf("kv.%p chain.%p\n",kv,coin->chain);
    (*inititem)(coin,kv,0,0,-1,valuesize,0);
    iguana_loadkvfile(coin,kv,valuesize,verifyitem,inititem,maxind);
    if ( initialnumitems != 0 )
        iguana_kvensure(coin,kv,initialnumitems);
    return(kv);
}

uint32_t iguana_syncs(struct iguana_info *coin)
{
    FILE *fp; char fnameold[512],fnameold2[512],fname[512],fname2[512]; int32_t i,height,flag = 0;
    if ( (coin->blocks.parsedblocks > coin->longestchain-1000 && (coin->blocks.parsedblocks % 100) == 1) ||
        (coin->blocks.parsedblocks > coin->longestchain-10000 && (coin->blocks.parsedblocks % 1000) == 1) ||
        (coin->blocks.parsedblocks > coin->longestchain-2000000 && (coin->blocks.parsedblocks % 10000) == 1) ||
        (coin->blocks.parsedblocks > coin->firstblock+100 && (coin->blocks.parsedblocks % 100000) == 1) )
    {
        if ( coin->blocks.parsedblocks > coin->loadedLEDGER.snapshot.height+2 )
            flag = 1;
    }
    if ( flag != 0 )
    {
        height = coin->blocks.parsedblocks - (coin->firstblock != 0);
        for (i=0; i<IGUANA_NUMAPPENDS; i++)
            printf("%llx ",(long long)coin->LEDGER.snapshot.lhashes[i].txid);
        char str[65];
        bits256_str(str,coin->LEDGER.snapshot.ledgerhash);
        printf("-> syncs %s ledgerhashes.%d\n",str,height);
        iguana_syncmap(&coin->iAddrs->M,0);
        iguana_syncmap(&coin->blocks.db->M,0);
        iguana_syncmap(&coin->unspents->M,0);
        iguana_syncmap(&coin->unspents->M2,0);
        iguana_syncmap(&coin->spends->M,0);
        iguana_syncmap(&coin->spends->M2,0);
        iguana_syncmap(&coin->txids->M,0);
        iguana_syncmap(&coin->pkhashes->M,0);
        iguana_syncmap(&coin->pkhashes->M2,0);
        iguana_syncmap(&coin->pkhashes->M3,0);
        printf("%s threads.%d iA.%d ranked.%d hwm.%u parsed.%u T.%d U.%d %.8f S.%d %.8f net %.8f P.%d\n",coin->symbol,iguana_numthreads(coin,-1),coin->numiAddrs,coin->peers.numranked,coin->blocks.hwmheight+1,height,coin->latest.dep.numtxids,coin->latest.dep.numunspents,dstr(coin->latest.credits),coin->latest.dep.numspends,dstr(coin->latest.debits),dstr(coin->latest.credits)-dstr(coin->latest.debits),coin->latest.dep.numpkinds);
        sprintf(fname,"tmp/%s/ledger.%d",coin->symbol,height);
        sprintf(fname2,"DB/%s/ledger",coin->symbol);
        sprintf(fnameold,"tmp/%s/ledger.old",coin->symbol);
        sprintf(fnameold2,"tmp/%s/ledger.old2",coin->symbol);
        iguana_renamefile(fnameold,fnameold2);
        iguana_renamefile(fname2,fnameold);
        if ( (fp= fopen(fname,"wb")) != 0 )
        {
            if ( fwrite(coin->accounts,sizeof(*coin->accounts),coin->LEDGER.snapshot.dep.numpkinds,fp) != coin->LEDGER.snapshot.dep.numpkinds )
                printf("WARNING: error saving %s accounts[%d]\n",fname,coin->LEDGER.snapshot.dep.numpkinds);
            if ( fwrite(&coin->LEDGER,1,sizeof(coin->LEDGER),fp) != sizeof(coin->LEDGER) )
                printf("WARNING: error saving %s\n",fname);
            fclose(fp);
            iguana_copyfile(fname,fname2,1);
        }
        printf("backups created\n");
    }
    return((uint32_t)time(NULL));
}

// 480a886f78a52d94 2c16330bdd8565f2 fbfb8ba91a6cd871 d1feb1e96190d4ff b8fef8854847e7db 8d2692bcfe41c777 ec86c8502288022f 789ebb3966bb640f -> pre parse 35ee0080a9a132e88477e8809a6e2a0696a06b8c7b13fbfde2955998346dd5c8 ledgerhashes.120000
// 9d1025feba33725a d69751b2f8d3f626 1f19457ce24411f1 76e12fd68b3b5b3c 2ad1a1e4b3b7014e a699f2904d073771 989c145c04a7a0d0 e888ab12de678518 -> syncs b8cf6b625de1d921695d1d2247ad68b86d047adf417c09562dc620ada993c47d ledgerhashes.140000
// 53faf4c08ae7cd66 60af0f6074a4460a 8fa0f21eb4996161 7d695aa60788e52c 45a5c96ef55a1797 7b3225a83646caec d2d5788986315066 27372b0616caacf0 -> syncs c874aa3554c69038574e7da352eb624ac539fed97bf73b605d00df0c8cec4c1b ledgerhashes.200000
// 739df50dbbaedada b83cbd69f08d2a0f 7a8ffa182706c5b7 8215ff6c7ffb9985 4d674a6d386bd759 f829283534a1804 aeb3b0644b01e07f 7ffe4899a261ca96 -> syncs fba47203d5c1d08e5cf55fa461f4deb6d0c97dcfa364ee5b51f0896ffcbcbaa7 ledgerhashes.300000
// 739df50dbbaedada b83cbd69f08d2a0f 7a8ffa182706c5b7 8215ff6c7ffb9985 4d674a6d386bd759 f829283534a1804 b5e66cbe3a2bdbea 7ffe4899a261ca96 -> syncs 6b3620ba67fad34a29dd86cd5ec9fe6afd2a81d8a5296aa33b03da74fdd20a9b ledgerhashes.300001

int32_t iguana_loadledger(struct iguana_info *coin,int32_t hwmheight)
{
    FILE *fp; char fname[512],mapname[512],newfname[512]; struct iguana_block *block; struct iguana_prevdep L;
    struct iguana_prevdep *dep; int32_t height,i,valid = 0;
    dep = &coin->latest.dep;
    sprintf(fname,"DB/%s/ledger",coin->symbol);
    mapname[0] = newfname[0] = 0;
    if ( (fp= fopen(fname,"rb")) == 0 )
    {
        sprintf(fname,"tmp/%s/ledger.old",coin->symbol);
        if ( (fp= fopen(fname,"rb")) == 0 )
        {
            sprintf(fname,"tmp/%s/ledger.old2",coin->symbol);
            fp = fopen(fname,"rb");
        }
    }
    if ( fp != 0 )
    {
        sprintf(mapname,"DB/%s/pkhashes2",coin->symbol);
        sprintf(newfname,"DB/%s/pkhashes2.over",coin->symbol);
        fseek(fp,-sizeof(coin->LEDGER),SEEK_END);
        if ( fread(&coin->LEDGER,1,sizeof(coin->LEDGER),fp) != sizeof(coin->LEDGER) )
            printf("WARNING: error loading %s\n",fname);
        if ( (block= iguana_blockptr(coin,coin->LEDGER.snapshot.height)) != 0 )
        {
            if ( memcmp(block->hash2.bytes,coin->LEDGER.snapshot.blockhash.bytes,sizeof(block->hash2)) == 0 )
            {
                fclose(fp);
                iguana_renamefile(mapname,newfname);
                iguana_renamefile(fname,mapname);
                *dep = coin->LEDGER.snapshot.dep;
                coin->loadedLEDGER = coin->LEDGER;
                memcpy(&coin->latest.ledgerhash,&coin->LEDGER.snapshot.ledgerhash,sizeof(coin->LEDGER.snapshot.ledgerhash));
                memcpy(coin->latest.lhashes,coin->LEDGER.snapshot.lhashes,sizeof(coin->LEDGER.snapshot.lhashes));
                memcpy(coin->latest.states,coin->LEDGER.snapshot.states,sizeof(coin->LEDGER.snapshot.states));
                printf("found ledger height.%d loadedht.%d\n",block->height,coin->LEDGER.snapshot.height); //getchar();
                for (i=0; i<IGUANA_NUMAPPENDS; i++)
                    printf("%llx ",(long long)coin->LEDGER.snapshot.lhashes[i].txid);
                char str[65];
                bits256_str(str,coin->LEDGER.snapshot.ledgerhash);
                printf("-> %s ledgerhashes.%x\n",str,calc_crc32(0,&coin->latest.states[IGUANA_LHASH_TXIDS],sizeof(coin->latest.states[IGUANA_LHASH_TXIDS])));
                printf("loaded H.%d T%d U%d S%d P%d\n",coin->LEDGER.snapshot.height,dep->numtxids,dep->numunspents,dep->numspends,dep->numpkinds); //getchar();
                coin->latest.credits = coin->LEDGER.snapshot.credits;
                coin->latest.debits = coin->LEDGER.snapshot.debits;
                coin->latest.dep.supply = (coin->LEDGER.snapshot.credits - coin->LEDGER.snapshot.debits);
                return(block->height);
            }
        }
        fclose(fp);
    }
    dep->numpkinds = dep->numtxids = dep->numunspents = dep->numspends = 1;
    while ( hwmheight > 0 )
    {
        if ( (block= iguana_blockptr(coin,hwmheight)) != 0 )
        {
            iguana_setdependencies(coin,block,&L);
            //printf("block.%d: T.%d (%d %d) U.%d S.%d A.%d\n",hwmheight,dep->numtxids,block->numvouts,block->numvins,dep->numunspents,dep->numspends,dep->numpkhashes);
            if ( L.numtxids != 0 && L.numunspents != 0 && L.numspends != 0 && block->numvouts != 0 && block->txn_count != 0 && L.numpkinds != 0 )
            {
                 if ( valid++ > 25 )
                    break;
            }
        } else printf("missing block.%d\n",hwmheight);
        hwmheight--;
    }
    for (height=0; height<=hwmheight; height++)
    {
        if ( iguana_setdependencies(coin,iguana_blockptr(coin,height),&L) < 0 )
            break;
        dep->numtxids = L.numtxids + 0*block->txn_count;
        dep->numunspents = L.numunspents + 0*block->numvouts;
        dep->numspends = L.numspends + 0*block->numvins;
        dep->numpkinds = L.numpkinds;
    }
    return(hwmheight);
}

int32_t iguana_validateramchain(struct iguana_info *coin,int64_t *netp,uint64_t *creditsp,uint64_t *debitsp,int32_t height,struct iguana_block *block,int32_t hwmheight,struct iguana_prevdep *lp)
{
    uint32_t i,n,m,u,txidind,unspentind,spendind,pkind,checkind,numvins,numvouts,txind,firstvout,firstvin,nextfirstvout,nextfirstvin; struct iguana_prevdep *nextlp;
    struct iguana_txid T,nextT; uint64_t credits,debits,nets; struct iguana_block *nextblock;
    credits = debits = nets = *creditsp = *debitsp = *netp = numvouts = numvins = 0;
    if ( block->height == height )
    {
        txidind = lp->numtxids, unspentind = lp->numunspents, spendind = lp->numspends, pkind = lp->numpkinds;
        //printf("validate.%d (t%d u%d s%d p%d)\n",height,txidind,unspentind,spendind,pkind);
        for (txind=0; txind<block->txn_count; txind++,txidind++)
        {
            T = coin->T[txidind], nextT = coin->T[txidind+1];
            //printf("h%d i%d T.%d (%d %d) -> (%d %d)\n",height,txind,txidind,T.firstvout,T.firstvin,nextT.firstvout,nextT.firstvin);
            if ( height == 0 && (T.firstvout == 0 || T.firstvin == 0) )
                return(-1);
            //printf(">>>> h%d i%d T.%d (%d %d) -> (%d %d) cmp.(%d %d)\n",height,txind,txidind,T.firstvout,T.firstvin,nextT.firstvout,nextT.firstvin,height == 0,(T.firstvout == 0 || T.firstvin == 0));
            if ( (checkind= iguana_txidind(coin,&firstvout,&firstvin,T.txid)) == txidind )
            {
                if ( T.firstvout != firstvout || T.firstvin != firstvin )
                {
                    printf("mismatched rwtxidind %d != %d, %d != %d\n",T.firstvout,firstvout,T.firstvin,firstvin);
                    getchar();
                    return(-1);
                }
                if ( txind == 0 && (firstvout != unspentind || firstvin != spendind) )
                {
                    char str[65];
                    bits256_str(str,T.txid);
                    printf("h.%d txind.%d txidind.%d %s firstvout.%d != U%d firstvin.%d != S%d\n",height,txind,txidind,str,firstvout,unspentind,firstvin,spendind);
                    iguana_txidind(coin,&firstvout,&firstvin,T.txid);
                    iguana_txidind(coin,&firstvout,&firstvin,T.txid);
                    return(-1);
                }
                nextfirstvout = nextT.firstvout, nextfirstvin = nextT.firstvin;
                if ( nextfirstvout < unspentind || nextfirstvin < spendind )
                {
                    printf("h.%d txind.%d nexttxidind.%d firstvout.%d != U%d firstvin.%d != S%d\n",height,txind,txidind,nextfirstvout,unspentind,nextfirstvin,spendind);
                    if ( nextfirstvout == 0 && nextfirstvin == 0 )
                    {
                        coin->T[txidind+1].firstvout = unspentind;
                        coin->T[txidind+1].firstvin = spendind;
                        printf("autofixed\n");
                    }
                    else
                    {
                        getchar();
                        return(-1);
                    }
                }
                n = (nextfirstvout - T.firstvout);
                m = (nextfirstvin - T.firstvin);
                //printf("height.%d n.%d m.%d U.(%d - %d) S.(%d - %d)\n",height,n,m,nextfirstvout,T.firstvout,nextfirstvin,T.firstvin);
                for (i=0; i<n; i++,unspentind++)
                {
                    credits += coin->U[unspentind].value;
                    if ( coin->Uextras[unspentind].spendind == 0 )
                        nets += coin->U[unspentind].value;
                    if ( coin->U[unspentind].pkind > pkind )
                        pkind = coin->U[unspentind].pkind;
                    //printf("i.%d: unspentind.%d\n",i,unspentind);
                }
                for (i=0; i<m; i++,spendind++)
                {
                    if ( (u= coin->S[spendind].unspentind) > 0 && u < coin->latest.dep.numunspents )
                        debits += coin->U[u].value;
                    else
                    {
                        printf("cant read spendind.%d or S.unspentind %d\n",spendind+i,u);
                        getchar();
                    }
                }
                numvouts += n;
                numvins += m;
            }
            else
            {
                char str[65];
                bits256_str(str,T.txid);
                printf("height.%d txind.%d txid.%s txidind.%d != %d\n",height,txind,str,txidind,checkind);
                getchar();
                return(-1);
            }
        }
        if ( numvins != block->numvins || numvouts != block->numvouts )
        {
            printf("height.%d numvins or numvouts error %d != %d || %d != %d\n",height,numvins,block->numvins,numvouts,block->numvouts);
            if ( block->numvins == 0 && block->numvouts == 0 )
            {
                block->numvins = numvins;
                block->numvouts = numvouts;
                iguana_kvwrite(coin,coin->blocks.db,0,block,(uint32_t *)&block->height);
                m = 0;//iguana_fixblocks(coin,height,hwmheight);
                printf("autocorrected.%d\n",m);
                exit(1);
            }
            else
            {
                getchar();
                return(-1);
            }
        }
        *creditsp = credits, *debitsp = debits, *netp = nets;
        if ( (nextblock= iguana_blockptr(coin,height+1)) != 0 )
        {
            nextlp = 0; 
            if ( 0 && lp->supply+credits-debits != nextlp->supply )
            {
                printf("nextblock.%d supply mismatch %.8f (%.8f - %.8f)  %.8f != %.8f\n",height+1,dstr(lp->supply),dstr(credits),dstr(debits),dstr(lp->supply+credits-debits),dstr(nextlp->supply));
                getchar();
                return(-1);
            }
            if ( txidind != nextlp->numtxids || unspentind != nextlp->numunspents || spendind != nextlp->numspends )//|| pkind+1 != nextlp->numpkinds )
            {
                printf("Block.(h%d t%d u%d s%d p%d) vs next.(h%d t%d u%d s%d p%d)\n",block->height,txidind,unspentind,spendind,pkind,height+1,nextlp->numtxids,nextlp->numunspents,nextlp->numspends,nextlp->numpkinds);
                return(-1);
            }
            return(0);
        }
        printf("cant find next block at %d\n",height+1);
        //printf("block.%d %.8f (%.8f - %.8f)\n",height,dstr(nets),dstr(credits),dstr(debits));
    } else printf("height mismatch %d != %d\n",height,block->height);
    //getchar();
    return(-1);
}

int32_t iguana_fixsecondary(struct iguana_info *coin,int32_t numtxids,int32_t numunspents,int32_t numspends,int32_t numpkinds,struct iguana_Uextra *Uextras,struct iguana_pkextra *pkextras,struct iguana_account *accounts)
{
    uint32_t i; int32_t m,err;
    if ( numtxids < 2 || numunspents < 2 || numspends < 2 || numpkinds < 2 )
        return(0);
    //struct iguana_Uextra { uint32_t spendind; }; // unspentind
    //struct iguana_unspent { uint64_t value; uint32_t pkind,txidind,prevunspentind; };
    for (i=m=err=0; i<numunspents; i++)
    {
        if ( Uextras[i].spendind >= numspends )
            m++, Uextras[i].spendind = 0;//, printf("%d ",Uextras[i].spendind);
        if ( coin->U[i].prevunspentind != 0 && coin->U[i].prevunspentind >= i )
            err++, printf("preverr.%d/%d ",coin->U[i].prevunspentind,i);
        if ( coin->U[i].txidind >= numtxids )
            err++, printf("errtxidind.%d ",coin->U[i].txidind);
        if ( coin->U[i].pkind >= numpkinds )
            err++, printf("errpkind.%d ",coin->U[i].pkind);
    }
    if ( (err+m) != 0 )
        iguana_syncmap(&coin->unspents->M2,0);
    printf("cleared %d Uextras before numunspents.%d beyond errs.%d\n",m,numunspents,err);
    if ( err != 0 )
        getchar();
    //struct iguana_pkextra { uint32_t firstspendind; }; // pkind
    for (i=m=0; i<numpkinds; i++)
    {
        if ( pkextras[i].firstspendind >= numspends )
            m++, pkextras[i].firstspendind = 0;//, printf("firstS.%d ",pkextras[i].firstspendind);
    }
    if ( m != 0 )
        iguana_syncmap(&coin->pkhashes->M3,0);
    printf("pkextras beyond numspends.%d m.%d accounts.%p\n",numspends,m,accounts);
    //struct iguana_spend { uint32_t unspentind,prevspendind; }; // dont need nextspend
    /*for (i=err=m=0; i<numspends; i++)
    {
        if ( coin->S[i].unspentind >= numunspents )
            err++, coin->S[i].unspentind = 0;//, printf("S->U%d ",coin->S[i].unspentind);
        //printf("%d ",coin->S[i].prevspendind);
        if ( coin->Sextras[i].prevspendind != 0 && coin->Sextras[i].prevspendind >= i )
            m++, coin->Sextras[i].prevspendind = 0, printf("preverr.%d:%d ",coin->Sextras[i].prevspendind,i);
    }
    printf("errs.%d in spends numspends.%d\n",err,numspends);
    if ( err != 0 )
        getchar();*/
    return(0);
}

void clearmem(void *ptr,int32_t len)
{
    static const uint8_t zeroes[512];
    if ( len > sizeof(zeroes) || memcmp(ptr,zeroes,len) != 0 )
        memset(ptr,0,len);
}

int32_t iguana_clearoverage(struct iguana_info *coin,int32_t numtxids,int32_t numunspents,int32_t numspends,int32_t numpkinds,struct iguana_Uextra *Uextras,struct iguana_pkextra *pkextras,struct iguana_account *accounts)
{
    uint32_t i,n;
    printf("clear txids\n");
    n = (uint32_t)((uint64_t)coin->txids->M.allocsize / coin->txids->HDDvaluesize) - 2;
    for (i=numtxids+1; i<n; i++) // diff with next txid's firstv's give numv's
        clearmem(&coin->T[i],sizeof(coin->T[i]));
    
    printf("clear pkinds\n");
    n = (uint32_t)((uint64_t)coin->pkhashes->M.allocsize / coin->pkhashes->HDDvaluesize) - 2;
    for (i=numpkinds; i<n; i++)
        clearmem(&coin->P[i],sizeof(coin->P[i]));
    n = (uint32_t)((uint64_t)coin->pkhashes->M2.allocsize / coin->pkhashes->valuesize2) - 2;
    for (i=numpkinds; i<n; i++)
        clearmem(&accounts[i],sizeof(accounts[i]));
    n = (uint32_t)((uint64_t)coin->pkhashes->M3.allocsize / coin->pkhashes->valuesize3) - 2;
    for (i=numpkinds; i<n; i++)
        pkextras[i].firstspendind = 0;
    
    printf("clear unspents\n");
    n = (uint32_t)((uint64_t)coin->unspents->M.allocsize / coin->unspents->HDDvaluesize) - 2;
    for (i=numunspents; i<n; i++)
        clearmem(&coin->U[i],sizeof(coin->U[i]));
    n = (uint32_t)((uint64_t)coin->unspents->M2.allocsize / coin->unspents->valuesize2) - 2;
    for (i=numunspents; i<n; i++)
        clearmem(&Uextras[i],sizeof(Uextras[i]));
    
    printf("clear spends\n");
    n = (uint32_t)((uint64_t)coin->spends->M.allocsize / coin->spends->HDDvaluesize) - 2;
    for (i=numspends; i<n; i++)
        clearmem(&coin->S[i],sizeof(coin->S[i]));
    //n = (uint32_t)((uint64_t)coin->spends->M2.allocsize / coin->spends->valuesize2) - 2;
    //for (i=numspends; i<n; i++)
    //    clearmem(&coin->Sextras[i],sizeof(coin->Sextras[i]));
    return(0);
}

int64_t iguana_verifybalances(struct iguana_info *coin,int32_t fullverify)
{
    int64_t err,balance = 0; int32_t i,numerrs = 0;
    for (i=0; i<coin->latest.dep.numpkinds; i++)
    {
        if ( fullverify != 0 )
        {
            if ( (err= iguana_verifyaccount(coin,&coin->accounts[i],i)) < 0 )
            {
                printf("err.%d from pkind.%d\n",(int32_t)err,i);
                numerrs++;
            }
        }
        balance += coin->accounts[i].balance;
    }
    printf("iguana_verifybalances %.8f numerrs.%d\n",dstr(balance),numerrs);
    if ( numerrs > 0 )
        getchar();
    return(balance);
}

int32_t iguana_initramchain(struct iguana_info *coin,int32_t hwmheight,int32_t mapflags,int32_t fullverify)
{
    struct iguana_prevdep *dep; struct iguana_block *block,lastblock; double lastdisp = 0.;
    // init sequence is very tricky. must be done in the right order and make sure to only use data
    // that has already been initialized. and at the end all the required fields need to be correct
    struct iguana_msghdr H; uint8_t buf[1024]; int32_t len,height,valid=0,flag=0;
    struct iguana_prevdep L,prevL;
    int64_t checkbalance,net,nets; uint64_t prevcredits,prevdebits,credit,debit,credits,debits,origsupply;
    dep = &coin->latest.dep;
    height = hwmheight;
    if ( (height= iguana_loadledger(coin,hwmheight)) < 0 )
    {
        printf("iguana_initramchain: unrecoverable loadledger error hwmheight.%d\n",hwmheight);
        return(-1);
    }
    hwmheight = height;
    printf("four ramchains start valid.%d height.%d txids.%d vouts.%d vins.%d pkhashes.%d\n",valid,hwmheight,dep->numtxids,dep->numunspents,dep->numspends,dep->numpkinds);
    //four ramchains start valid.0 height.316904 txids.45082870 vouts.27183907 vins.107472009 pkhashes.44807925 3.57 minutes

    coin->unspents = iguana_stateinit(coin,IGUANA_ITEMIND_DATA,coin->symbol,coin->symbol,"unspents",0,0,sizeof(struct iguana_unspent),sizeof(struct iguana_unspent),100000,iguana_verifyunspent,iguana_nullinit,sizeof(*coin->Uextras),0,dep->numunspents,2500000,0);
    if ( coin->unspents == 0 )
        printf("cant create unspents\n"), exit(1);
    coin->unspents->HDDitemsp = (void **)&coin->U, coin->U = coin->unspents->M.fileptr;
    coin->unspents->HDDitems2p = (void **)&coin->Uextras, coin->Uextras = coin->unspents->M2.fileptr;
    printf("four ramchains start valid.%d height.%d txids.%d vouts.%d vins.%d pkhashes.%d %.2f minutes\n",valid,hwmheight,dep->numtxids,dep->numunspents,dep->numspends,dep->numpkinds,((double)time(NULL)-coin->starttime)/60.);
    
    coin->spends = iguana_stateinit(coin,IGUANA_ITEMIND_DATA,coin->symbol,coin->symbol,"spends",0,0,sizeof(struct iguana_spend),sizeof(struct iguana_spend),100000,iguana_verifyspend,iguana_nullinit,0,0,dep->numspends,2500000,0);
    if ( coin->spends == 0 )
        printf("cant create spends\n"), exit(1);
    printf("four ramchains start valid.%d height.%d txids.%d vouts.%d vins.%d pkhashes.%d %.2f minutes\n",valid,hwmheight,dep->numtxids,dep->numunspents,dep->numspends,dep->numpkinds,((double)time(NULL)-coin->starttime)/60.);
    coin->spends->HDDitemsp = (void **)&coin->S, coin->S = coin->spends->M.fileptr;
    coin->spends->HDDitems2p = (void **)&coin->Sextras, coin->Sextras = coin->spends->M2.fileptr;

    coin->txids = iguana_stateinit(coin,IGUANA_ITEMIND_DATA|((mapflags&IGUANA_MAPTXIDITEMS)!=0)*IGUANA_MAPPED_ITEM,coin->symbol,coin->symbol,"txids",0,sizeof(bits256),sizeof(struct iguana_txid),sizeof(struct iguana_txid),100000,iguana_verifytxid,iguana_inittxid,0,0,dep->numtxids,1000000,0);
    if ( coin->txids == 0 )
        printf("cant create txids\n"), exit(1);
    coin->txids->HDDitemsp = (void **)&coin->T, coin->T = coin->txids->M.fileptr;
    printf("four ramchains start valid.%d height.%d txids.%d vouts.%d vins.%d pkhashes.%d %.2f minutes\n",valid,hwmheight,dep->numtxids,dep->numunspents,dep->numspends,dep->numpkinds,((double)time(NULL)-coin->starttime)/60.);
    
    coin->pkhashes = iguana_stateinit(coin,IGUANA_ITEMIND_DATA|((mapflags&IGUANA_MAPPKITEMS)!=0)*IGUANA_MAPPED_ITEM,coin->symbol,coin->symbol,"pkhashes",0,20,sizeof(struct iguana_pkhash),sizeof(struct iguana_pkhash),100000,iguana_verifypkhash,iguana_nullinit,sizeof(*coin->accounts),sizeof(*coin->pkextras),dep->numpkinds,1000000,0);
    if ( coin->pkhashes == 0 )
        printf("cant create pkhashes\n"), exit(1);
    coin->pkhashes->HDDitemsp = (void **)&coin->P, coin->P = coin->pkhashes->M.fileptr;
    coin->pkhashes->HDDitems2p = (void **)&coin->accounts, coin->accounts = coin->pkhashes->M2.fileptr;
    coin->pkhashes->HDDitems3p = (void **)&coin->pkextras, coin->pkextras = coin->pkhashes->M3.fileptr;
    printf("four ramchains start valid.%d height.%d txids.%d vouts.%d vins.%d pkhashes.%d %.2f minutes\n",valid,hwmheight,dep->numtxids,dep->numunspents,dep->numspends,dep->numpkinds,((double)time(NULL)-coin->starttime)/60.);
    
    iguana_kvensure(coin,coin->txids,dep->numtxids + coin->txids->incr);
    iguana_kvensure(coin,coin->pkhashes,dep->numpkinds + coin->pkhashes->incr);
    iguana_kvensure(coin,coin->unspents,dep->numunspents + coin->unspents->incr);
    iguana_kvensure(coin,coin->spends,dep->numspends + coin->spends->incr);
    coin->txids->numkeys = dep->numtxids;
    coin->unspents->numkeys = dep->numunspents;
    coin->spends->numkeys = dep->numspends;
    coin->pkhashes->numkeys = dep->numpkinds;
    iguana_fixsecondary(coin,dep->numtxids,dep->numunspents,dep->numspends,dep->numpkinds,coin->Uextras,coin->pkextras,coin->accounts);
    printf("hwmheight.%d KV counts T.%d P.%d U.%d S.%d\n",hwmheight,coin->txids->numkeys,coin->pkhashes->numkeys,coin->unspents->numkeys,coin->spends->numkeys);
    memset(&lastblock,0,sizeof(lastblock));
    origsupply = dep->supply, dep->supply = 0;
    for (prevcredits=prevdebits=credits=debits=nets=height=0; height<=hwmheight; height++)
    {
        if ( hwmheight > 10000 && ((double)height / hwmheight) > lastdisp+.01 )
        {
            fprintf(stderr,"%.0f%% ",100. * lastdisp);
            lastdisp = ((double)height / hwmheight);
        }
        if ( (block= iguana_blockptr(coin,height)) == 0 )
        {
            printf("error getting height.%d\n",height);
            break;
        }
        lastblock = *block;
        if ( height == hwmheight )
            break;
        printf("need to set valid L\n");
        if ( iguana_validateramchain(coin,&net,&credit,&debit,height,block,hwmheight,&L) < 0 )
        {
            printf("UNRECOVERABLE error iguana_validateramchain height.%d\n",height);
            getchar();
            exit(1);
            break;
        }
        nets += net, credits += credit, debits += debit;
        if ( nets != (credits - debits) )
        {
            //printf("height.%d: net %.8f != %.8f (%.8f - %.8f)\n",height,dstr(nets),dstr(credits)-dstr(debits),dstr(credits),dstr(debits));
            //break;
        }
        prevcredits = credits;
        prevdebits = debits;
    }
    if ( lastblock.height == 0 )
        dep->numpkinds = dep->numspends = dep->numtxids = dep->numunspents = 1, dep->supply = 0, coin->latest.credits = coin->latest.debits = 0;
    else
    {
        printf("set prevL\n");
        dep->numtxids = prevL.numtxids;
        dep->numunspents = prevL.numunspents;
        dep->numspends = prevL.numspends;
        dep->numpkinds = prevL.numpkinds;
        dep->supply = prevL.supply;
        coin->latest.credits = prevcredits;
        coin->latest.debits = prevdebits;
        if ( dep->supply != (prevcredits - prevdebits) )
        {
            printf("override supply %.8f (%.8f - %.8f)\n",dstr(dep->supply),dstr(prevcredits),dstr(prevdebits));
            dep->supply = (prevcredits - prevdebits);
        }
        checkbalance = iguana_verifybalances(coin,0);
        if ( (checkbalance != dep->supply || fullverify != 0) && iguana_verifybalances(coin,1) != dep->supply )
        {
            printf("balances mismatch\n");
            getchar();
        }
    }
    coin->txids->numkeys = dep->numtxids;
    coin->unspents->numkeys = dep->numunspents;
    coin->spends->numkeys = dep->numspends;
    coin->pkhashes->numkeys = dep->numpkinds;
    coin->blocks.parsedblocks = lastblock.height;
    printf("\nhwmheight.%d KV counts T.%d P.%d U.%d S.%d %.8f (%.8f - %.8f)\n",hwmheight,coin->txids->numkeys,coin->pkhashes->numkeys,coin->unspents->numkeys,coin->spends->numkeys,dstr(coin->latest.dep.supply),dstr(coin->latest.credits),dstr(coin->latest.debits));
    printf("four ramchains start valid.%d height.%d txids.%d vouts.%d vins.%d pkhashes.%d %.2f minutes\n",valid,hwmheight,dep->numtxids,dep->numunspents,dep->numspends,dep->numpkinds,((double)time(NULL)-coin->starttime)/60.);
    printf("height.%d after validateramchain hwmheight.%d flag.%d parsed.%d\n",height,hwmheight,flag,coin->blocks.parsedblocks); //getchar();
    if ( coin->blocks.parsedblocks == 0 )
    {
        uint8_t txspace[32768]; struct iguana_memspace MEM;
        len = (int32_t)strlen(coin->chain->genesis_hex)/2;
        decode_hex(buf,len,(char *)coin->chain->genesis_hex);
        iguana_sethdr(&H,coin->chain->netmagic,"block",buf,len);
        iguana_meminit(&MEM,"genesis",txspace,sizeof(txspace),0);
        iguana_parser(coin,0,&MEM,&MEM,&MEM,&H,buf,len);
        printf("coin->blocks.parsedblocks.%d KV counts T.%d P.%d U.%d S.%d\n",coin->blocks.parsedblocks,coin->txids->numkeys,coin->pkhashes->numkeys,coin->unspents->numkeys,coin->spends->numkeys);
        printf("auto parse genesis\n"); //getchar();
    }
    else iguana_clearoverage(coin,dep->numtxids,dep->numunspents,dep->numspends,dep->numpkinds,coin->Uextras,coin->pkextras,coin->accounts);
    return(coin->blocks.parsedblocks);
}

struct iguana_info *iguana_startcoin(struct iguana_info *coin,int32_t initialheight,int32_t mapflags)
{
    FILE *fp; char fname[512],*symbol; int32_t iter,height; struct iguana_block space;
    coin->sleeptime = 10000;
    symbol = coin->symbol;
    if ( initialheight < coin->chain->bundlesize*10 )
        initialheight = coin->chain->bundlesize*10;
    //coin->R.maprecvdata = ((mapflags & IGUANA_MAPRECVDATA) != 0);
    iguana_recvalloc(coin,initialheight);
    coin->iAddrs = iguana_stateinit(coin,IGUANA_ITEMIND_DATA|((mapflags&IGUANA_MAPPEERITEMS)!=0)*IGUANA_MAPPED_ITEM,symbol,symbol,"iAddrs",0,sizeof(uint32_t),sizeof(struct iguana_iAddr),sizeof(struct iguana_iAddr),10000,iguana_verifyiAddr,iguana_initiAddr,0,0,0,0,1);
    
    coin->longestchain = 1;
    coin->blocks.hwmheight = 1;//iguana_lookahead(coin,&hash2,0);
    if ( 0 )
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
    }
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
    if ( (coin->MAXBUNDLES= coin->bundlescount / 3) < _IGUANA_MAXBUNDLES )
        coin->MAXBUNDLES = _IGUANA_MAXBUNDLES;
    //coin->peers.acceptloop = iguana_launch("acceptloop",iguana_acceptloop,coin,IGUANA_PERMTHREAD);
    //coin->peers.recvloop = iguana_launch("recvloop",iguana_recvloop,coin,IGUANA_PERMTHREAD);
    printf("started.%s\n",coin->symbol);
    return(coin);
}

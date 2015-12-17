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
#define IGUANA_MARKER 0x07770777

void iguana_peerfilename(struct iguana_info *coin,char *fname,uint32_t addrind,uint32_t filecount)
{
    sprintf(fname,"tmp/%s/peer%d.%d",coin->symbol,addrind,filecount);
}

struct iguana_txdatabits iguana_calctxidbits(uint32_t addrind,uint32_t filecount,uint32_t fpos,uint32_t datalen)
{
    struct iguana_txdatabits bits;
    if ( (bits.addrind= addrind) != addrind )
        printf("iguana_calctxidbits: addrind overflow.%d\n",addrind), exit(-1);
    if ( (bits.filecount= filecount) != filecount )
        printf("iguana_calctxidbits: filecount overflow.%d\n",filecount), exit(-1);
    if ( (bits.fpos= fpos) != fpos )
        printf("iguana_calctxidbits: fpos overflow.%d\n",fpos), exit(-1);
    if ( (bits.datalen= datalen) != datalen )
        printf("iguana_calctxidbits: datalen overflow.%d\n",datalen), exit(-1);
        return(bits);
}

int32_t iguana_peerfilecloseHT(struct iguana_info *coin,uint32_t addrind,uint32_t filecount)
{
    char fname[512]; int32_t i,n = 0; struct iguana_mappedptr *M;
return(0);
    iguana_peerfilename(coin,fname,addrind,filecount);
    printf("PEERFILECLOSE.%s\n",fname);
    //portable_mutex_lock(&coin->peers.filesM_mutex);
    if ( coin->peers.filesM != 0 )
    {
        for (i=0; i<coin->peers.numfilesM; i++)
        {
            M = &coin->peers.filesM[i];
            if ( strcmp(fname,M->fname) == 0 && M->fileptr != 0 )
            {
                printf("[%d] closemap.(%s)\n",i,fname);
                iguana_closemap(M);
                M->closetime = (uint32_t)time(NULL);
                n++;
            }
        }
    }
    //portable_mutex_unlock(&coin->peers.filesM_mutex);
    return(n);
}

void *_iguana_txdataptrHT(struct iguana_info *coin,struct iguana_mappedptr *M,char *fname,struct iguana_txdatabits txdatabits)
{
    int32_t len; uint8_t *rawptr; uint32_t starttime = (uint32_t)time(NULL);
    if ( M->fileptr != 0 )
    {
        while ( M->allocsize < (txdatabits.fpos + txdatabits.datalen + sizeof(uint32_t)) )
        {
            iguana_closemap(M);
            if ( iguana_mappedptr(0,M,0,0,fname) == 0 || M->allocsize < (txdatabits.fpos + txdatabits.datalen + sizeof(uint32_t)) )
            {
                if ( time(NULL) > starttime+3 )
                {
                    printf("too small (%s) %llu vs %ld\n",fname,(long long)M->allocsize,(txdatabits.fpos + txdatabits.datalen + sizeof(uint32_t)));
                    return(0);
                } else sleep(1);
            }
        }
        rawptr = (void *)((long)M->fileptr + txdatabits.fpos);
        memcpy(&len,rawptr,sizeof(len));
        if ( len == IGUANA_MARKER )
        {
            memcpy(&len,&rawptr[sizeof(len)],sizeof(len));
            //printf("found marker %s[%u] numblocks.%d\n",fname,(int32_t)txdatabits.fpos,len);
            if ( txdatabits.isdir != 0 )
                return(&rawptr[sizeof(uint32_t)*2]);
            else printf("isdir notset with IGUANA_MARKER.%x\n",IGUANA_MARKER);
        }
        else if ( len == txdatabits.datalen && len < IGUANA_MAXPACKETSIZE )
        {
            if ( txdatabits.isdir == 0 )
                return(&rawptr[sizeof(uint32_t)]);
            else printf("isdir set without IGUANA_MARKER.%x\n",IGUANA_MARKER);
        } else printf("txdataptr.%s: len.%d error [%d %d %d %d] (%d %d)\n",fname,len,txdatabits.datalen,txdatabits.addrind,txdatabits.fpos,txdatabits.filecount,len == txdatabits.datalen,len < IGUANA_MAXPACKETSIZE);//, getchar();
    } //else printf("txdataptr.%s %p %ld vs %ld\n",M->fname,M->fileptr,M->allocsize,(txdatabits.fpos + txdatabits.datalen + sizeof(uint32_t)));
    return(0);
}

void *iguana_peerfileptrHT(struct iguana_info *coin,struct iguana_txdatabits txdatabits,int32_t createflag)
{
    char fname[512]; int32_t i,oldesti,oldest,duration,datalen; uint64_t fpos; struct iguana_mappedptr *M = 0; void *ptr = 0;
    fpos = txdatabits.fpos, datalen = txdatabits.datalen;
    oldesti = -1;
    oldest = 0;
    iguana_peerfilename(coin,fname,txdatabits.addrind,txdatabits.filecount);
    //portable_mutex_lock(&coin->peers.filesM_mutex);
    if ( coin->peers.filesM != 0 )
    {
        for (i=0; i<coin->peers.numfilesM; i++)
        {
            M = &coin->peers.filesM[i];
            if ( strcmp(fname,M->fname) == 0 )
            {
                if ( M->fileptr != 0 && (ptr= _iguana_txdataptrHT(coin,M,fname,txdatabits)) != 0 )
                {
                    //portable_mutex_unlock(&coin->peers.filesM_mutex);
                    //printf("peerfileptr.(%s) %d %d -> %p\n",fname,txdatabits.addrind,txdatabits.filecount,ptr);
                    return(ptr);
                }
                else if ( M->closetime != 0 )
                {
                    duration = (uint32_t)(time(NULL) - M->closetime);
                    if ( duration > oldest )
                        oldest = duration, oldesti = i;
                }
            }
        }
        M = 0;
    }
    if ( createflag != 0 )
    {
        if ( oldesti >= 0 && oldest > 60 )
        {
            M = &coin->peers.filesM[oldesti];
            printf("oldesti.%d oldest.%d remove.(%s) recycle slot.%d\n",oldesti,oldest,M->fname,i);
            iguana_removefile(M->fname,0);
            memset(M,0,sizeof(*M));
        }
        if ( M == 0 )
        {
            coin->peers.filesM = myrealloc('m',coin->peers.filesM,coin->peers.filesM==0?0:coin->peers.numfilesM * sizeof(*coin->peers.filesM),(coin->peers.numfilesM+1) * sizeof(*coin->peers.filesM));
            M = &coin->peers.filesM[coin->peers.numfilesM];
            coin->peers.numfilesM++;
            //if ( (coin->peers.numfilesM % 10) == 0 )
                printf("iguana_peerfileptr realloc filesM.%d\n",coin->peers.numfilesM);
        }
        if ( iguana_mappedptr(0,M,0,0,fname) != 0 )
        {
            ptr = _iguana_txdataptrHT(coin,M,fname,txdatabits);
            printf("mapped.(%s) size.%ld %p\n",fname,(long)M->allocsize,ptr);
        } else printf("iguana_peerfileptr error mapping.(%s)\n",fname);
    }
    //portable_mutex_unlock(&coin->peers.filesM_mutex);
    return(ptr);
}

struct iguana_fileitem *iguana_peerdirptrHT(struct iguana_info *coin,int32_t *nump,uint32_t addrind,uint32_t filecount,int32_t createflag)
{
    char fname[512]; FILE *fp; uint32_t dirpos,marker; struct iguana_txdatabits txdatabits;
    *nump = 0;
    if ( filecount >= coin->peers.active[addrind].filecount )
        return(0);
    iguana_peerfilename(coin,fname,addrind,filecount);
    if ( (fp= fopen(fname,"rb")) != 0 )
    {
        fseek(fp,-sizeof(int32_t) * 3,SEEK_END);
        fread(nump,1,sizeof(*nump),fp);
        fread(&dirpos,1,sizeof(dirpos),fp);
        fread(&marker,1,sizeof(marker),fp);
        if ( marker == IGUANA_MARKER && (dirpos + sizeof(uint32_t) * 5 + *nump * sizeof(struct iguana_fileitem)) == ftell(fp) )
        {
            txdatabits = iguana_calctxidbits(addrind,filecount,dirpos,(int32_t)(*nump * sizeof(struct iguana_fileitem)));
            fclose(fp);
            txdatabits.isdir = 1;
            return(iguana_peerfileptrHT(coin,txdatabits,1));
        }
        else //if ( marker == IGUANA_MARKER )
            printf("marker.%x vs %x: dirpos.%d num.%d -> %ld vs %ld\n",marker,IGUANA_MARKER,dirpos,*nump,dirpos + sizeof(uint32_t) * 4 + *nump * sizeof(struct iguana_fileitem),ftell(fp));
        fclose(fp);
    } else printf("cant open dir.(%s)\n",fname);
    return(0);
}

struct iguana_ramchain *iguana_bundlemergeHT(struct iguana_info *coin,struct iguana_memspace *mem,struct iguana_memspace *memB,void *ptrs[],int32_t n,struct iguana_bundle *bp)
{
    int32_t i; struct iguana_ramchain *ramchain=0,*ramchainB; struct iguana_block *block;
    if ( ptrs[0] != 0 && (block= bp->blocks[0]) != 0 && (ramchain= iguana_ramchaininit(coin,mem,ptrs[0],bp->prevbundlehash2,block->prev_block,block->hash2,0,block->txdatabits.datalen)) != 0 )
    {
        for (i=1; i<n; i++)
        {
            iguana_memreset(memB);
            if ( ptrs[i] != 0 && (block= bp->blocks[i]) != 0 && (ramchainB= iguana_ramchaininit(coin,memB,ptrs[i],bp->prevbundlehash2,block->prev_block,block->hash2,i,block->txdatabits.datalen)) != 0 )
            {
                if ( iguana_ramchainmerge(coin,mem,ramchain,memB,ramchainB) < 0 )
                {
                    printf("error merging ramchain.%s hdrsi.%d at ptrs[%d]\n",coin->symbol,bp->hdrsi,i);
                    iguana_ramchainfree(coin,memB,ramchainB);
                    iguana_ramchainfree(coin,mem,ramchain);
                    return(0);
                }
                iguana_ramchainfree(coin,memB,ramchainB);
            }
            else
            {
                printf("error generating ramchain.%s hdrsi.%d for ptrs[%d]\n",coin->symbol,bp->hdrsi,i);
                iguana_ramchainfree(coin,mem,ramchain);
                return(0);
            }
        }
    }
    return(ramchain);
}

int32_t iguana_bundlesaveHT(struct iguana_info *coin,struct iguana_memspace *mem,struct iguana_memspace *memB,struct iguana_bundle *bp) // helper thread
{
    void *ptrs[IGUANA_MAXBUNDLESIZE]; uint32_t inds[IGUANA_MAXBUNDLESIZE][2]; struct iguana_fileitem *dir;
    struct iguana_bundle *itembp; int32_t addrind,bundlei,finished,fileind,i,j,maxrecv,num,flag,numdirs=0;
    struct iguana_txdatabits txdatabits; struct iguana_ramchain *ramchain; uint64_t estimatedsize = 0;
    struct iguana_block *block;
    memset(ptrs,0,sizeof(ptrs)), memset(inds,0,sizeof(inds));
    flag = maxrecv = 0;
    for (i=0; i<bp->n && i<coin->chain->bundlesize; i++)
    {
        if ( (block= bp->blocks[i]) != 0 )
        {
            txdatabits = block->txdatabits;
            if ( memcmp(block->hash2.bytes,coin->chain->genesis_hashdata,sizeof(bits256)) == 0 )
                ptrs[i] = coin->chain->genesis_hashdata, flag++;
            else if ( (ptrs[i]= iguana_peerfileptrHT(coin,txdatabits,1)) != 0 )
            {
                if ( block->recvlen > maxrecv )
                    maxrecv = block->recvlen;
                estimatedsize += block->recvlen;
                flag++;
            }
            else
            {
                printf("peerfileptr[%d] (%d %d %d %d) null bp.%p %d\n",i,txdatabits.addrind,txdatabits.filecount,txdatabits.fpos,txdatabits.datalen,bp,bp->hdrsi);
                if ( 1 )
                {
                    CLEARBIT(bp->recv,i);
                    bp->issued[i] = 0;
                    memset(&block->txdatabits,0,sizeof(block->txdatabits));
                    block = 0;
                }
            }
            addrind = txdatabits.addrind, fileind = txdatabits.filecount;
            if ( numdirs > 0 )
            {
                for (j=0; j<numdirs; j++)
                {
                    if ( inds[j][0] == addrind && inds[j][1] == fileind )
                        break;
                }
            } else j = 0;
            if ( j == numdirs )
            {
                inds[j][0] = addrind;
                inds[j][1] = fileind;
                numdirs++;
            }
        }
    }
    if ( flag == i )
    {
        iguana_meminit(mem,"bundleHT",0,estimatedsize + IGUANA_MAXPACKETSIZE,0);
        iguana_meminit(memB,"ramchainB",0,maxrecv + IGUANA_MAXPACKETSIZE,0);
        printf(">>>>>>>>> start MERGE.(%ld %ld) numdirs.%d i.%d flag.%d estimated.%ld maxrecv.%d\n",(long)mem->totalsize,(long)memB->totalsize,numdirs,i,flag,(long)estimatedsize,maxrecv);
        if ( (ramchain= iguana_bundlemergeHT(coin,mem,memB,ptrs,i,bp)) != 0 )
        {
            iguana_ramchainsave(coin,mem,ramchain);
            iguana_ramchainfree(coin,mem,ramchain);
            bp->emitfinish = (uint32_t)time(NULL);
        } else bp->emitfinish = 0;
        iguana_mempurge(mem);
        iguana_mempurge(memB);
        for (j=0; j<numdirs; j++)
        {
            finished = 0;
            if ( (dir= iguana_peerdirptrHT(coin,&num,inds[j][0],inds[j][1],1)) != 0 )
            {
                for (i=0; i<num; i++)
                {
                    if ( (itembp= iguana_bundlesearch(coin,&bundlei,dir[i].hash2)) != 0 )
                    {
                        //printf("dir[i.%d] j.%d %s %d[%d] %u\n",i,j,bits256_str(str,dir[i].hash2),itembp->hdrsi,bundlei,itembp->emitfinish);
                        if ( itembp->emitfinish != 0 )
                            finished++;
                    }
                }
                if ( finished == num )
                    iguana_peerfilecloseHT(coin,inds[j][0],inds[j][1]);
                else printf("peerdir.(%d %d) finished.%d of %d\n",inds[j][0],inds[j][1],finished,num);
            } else printf("cant get peerdirptr.(%d %d)\n",inds[j][0],inds[j][1]);
        }
    }
    else
    {
        printf(">>>>> bundlesaveHT error: numdirs.%d i.%d flag.%d\n",numdirs,i,flag);
        bp->emitfinish = 0;
    }
    return(flag);
}

void iguana_emitQ(struct iguana_info *coin,struct iguana_bundle *bp)
{
    struct iguana_helper *ptr;
    ptr = mycalloc('i',1,sizeof(*ptr));
    ptr->allocsize = sizeof(*ptr);
    ptr->coin = coin;
    ptr->bp = bp, ptr->hdrsi = bp->hdrsi;
    ptr->type = 'E';
    printf("%s EMIT.%d[%d] emitfinish.%u\n",coin->symbol,ptr->hdrsi,bp->n,bp->emitfinish);
    queue_enqueue("helperQ",&helperQ,&ptr->DL,0);
}

/*void iguana_txdataQ(struct iguana_info *coin,struct iguana_peer *addr,FILE *fp,long fpos,int32_t datalen)
{
    struct iguana_helper *ptr;
    ptr = mycalloc('i',1,sizeof(*ptr));
    ptr->allocsize = sizeof(*ptr);
    ptr->coin = coin;
    ptr->addr = addr, ptr->fp = fp, ptr->fpos = fpos, ptr->datalen = datalen;
    ptr->type = 'T';
    queue_enqueue("helperQ",&helperQ,&ptr->DL,0);
}*/

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
    struct iguana_helper *ptr; struct iguana_info *coin; struct iguana_memspace MEM,MEMB;
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
    memset(&MEM,0,sizeof(MEM)), memset(&MEMB,0,sizeof(MEMB));
    while ( 1 )
    {
        flag = 0;
        while ( (ptr= queue_dequeue(&helperQ,0)) != 0 )
        {
            iguana_helpertask(fp,&MEM,&MEMB,ptr);
            myfree(ptr,ptr->allocsize);
            flag++;
        }
        if ( flag == 0 )
        {
            for (i=0; i<sizeof(Coins)/sizeof(*Coins); i++)
            {
                coin = &Coins[i];
                if ( coin->launched != 0 )
                    flag += iguana_rpctest(coin);
            }
            if ( flag == 0 )
                usleep(10000);
        }
    }
}



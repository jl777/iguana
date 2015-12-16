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

void *iguana_txdataptr(struct iguana_info *coin,struct iguana_mappedptr *M,char *fname,struct iguana_txdatabits txdatabits)
{
    int32_t len; uint8_t *rawptr;
    if ( M->fileptr != 0 )//&& M->allocsize >= (txdatabits.fpos + txdatabits.datalen + sizeof(uint32_t)) )
    {
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
        } else printf("txdataptr: len.%d error %d (%d %d)\n",len,txdatabits.datalen,len == txdatabits.datalen,len < IGUANA_MAXPACKETSIZE);
    } //else printf("txdataptr.%s %p %ld vs %ld\n",M->fname,M->fileptr,M->allocsize,(txdatabits.fpos + txdatabits.datalen + sizeof(uint32_t)));
    return(0);
}

void *iguana_peerfileptr(struct iguana_info *coin,struct iguana_txdatabits txdatabits,int32_t createflag)
{
    char fname[512]; int32_t i,oldesti,oldest,duration,datalen; uint64_t fpos; struct iguana_mappedptr *M = 0; void *ptr = 0;
    fpos = txdatabits.fpos, datalen = txdatabits.datalen;
    oldesti = -1;
    oldest = 0;
    iguana_peerfilename(coin,fname,txdatabits.addrind,txdatabits.filecount);
    portable_mutex_lock(&coin->peers.filesM_mutex);
    if ( coin->peers.filesM != 0 )
    {
        for (i=0; i<coin->peers.numfilesM; i++)
        {
            M = &coin->peers.filesM[i];
            if ( strcmp(fname,M->fname) == 0 )
            {
                if ( M->fileptr != 0 && (ptr= iguana_txdataptr(coin,M,fname,txdatabits)) != 0 )
                {
                    portable_mutex_unlock(&coin->peers.filesM_mutex);
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
            if ( (coin->peers.numfilesM % 10) == 0 )
                printf("iguana_peerfileptr realloc filesM.%d\n",coin->peers.numfilesM);
        }
        if ( iguana_mappedptr(0,M,0,0,fname) != 0 )
        {
            ptr = iguana_txdataptr(coin,M,fname,txdatabits);
            printf("mapped.(%s) size.%ld %p\n",fname,(long)M->allocsize,ptr);
        } else printf("iguana_peerfileptr error mapping.(%s)\n",fname);
    }
    portable_mutex_unlock(&coin->peers.filesM_mutex);
    return(ptr);
}

int32_t iguana_peerfileclose(struct iguana_info *coin,uint32_t addrind,uint32_t filecount)
{
    char fname[512]; int32_t i,n = 0; struct iguana_mappedptr *M;
    iguana_peerfilename(coin,fname,addrind,filecount);
    printf("PEERFILECLOSE.%s\n",fname);
    portable_mutex_lock(&coin->peers.filesM_mutex);
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
    portable_mutex_unlock(&coin->peers.filesM_mutex);
    return(n);
}

struct iguana_fileitem *iguana_peerdirptr(struct iguana_info *coin,int32_t *nump,uint32_t addrind,uint32_t filecount,int32_t createflag)
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
            return(iguana_peerfileptr(coin,txdatabits,1));
        }
        else //if ( marker == IGUANA_MARKER )
            printf("marker.%x vs %x: dirpos.%d num.%d -> %ld vs %ld\n",marker,IGUANA_MARKER,dirpos,*nump,dirpos + sizeof(uint32_t) * 4 + *nump * sizeof(struct iguana_fileitem),ftell(fp));
        fclose(fp);
    } else printf("cant open dir.(%s)\n",fname);
    return(0);
}

struct iguana_txdatabits iguana_peerfilePT(struct iguana_info *coin,struct iguana_peer *addr,bits256 hash2,struct iguana_txdatabits txdatabits,int32_t datalen)
{
    char fname[512]; int32_t marker; uint32_t dirpos;
    if ( bits256_nonz(hash2) == 0 || addr->fp == 0 || ftell(addr->fp)+datalen >= IGUANA_PEERFILESIZE-IGUANA_MAXPACKETSIZE || addr->numfilehash2 >= addr->maxfilehash2 )
    //if ( addr->fp == 0 )
    {
        if ( addr->fp != 0 )
        {
            dirpos = (uint32_t)ftell(addr->fp);
            marker = IGUANA_MARKER;
            fwrite(&marker,1,sizeof(marker),addr->fp);
            fwrite(&addr->numfilehash2,1,sizeof(addr->numfilehash2),addr->fp);
            fwrite(addr->filehash2,addr->numfilehash2,sizeof(*addr->filehash2),addr->fp);
            fwrite(&addr->numfilehash2,1,sizeof(addr->numfilehash2),addr->fp);
            fwrite(&dirpos,1,sizeof(dirpos),addr->fp);
            fwrite(&marker,1,sizeof(marker),addr->fp);
            fclose(addr->fp);
            //iguana_flushQ(coin,addr);
            //fflush(addr->fp);
        }
        iguana_peerfilename(coin,fname,addr->addrind,++addr->filecount);
        txdatabits.filecount = addr->filecount;
        addr->fp = fopen(fname,"wb");
        addr->numfilehash2 = 0;
    }
    if ( addr->fp == 0 )
    {
        printf("error creating fileind.%d %s\n",addr->filecount,addr->ipaddr);
        exit(1);
    }
    if ( addr->numfilehash2 < addr->maxfilehash2 )
    {
        if ( addr->filehash2 == 0 )
            addr->filehash2 = mycalloc('f',addr->maxfilehash2,sizeof(*addr->filehash2));
        addr->filehash2[addr->numfilehash2].hash2 = hash2;
        //(*txdatabitsptrp) = &addr->filehash2[addr->numfilehash2].txdatabits;
        addr->filehash2[addr->numfilehash2].txdatabits = txdatabits;
        addr->numfilehash2++;
    }
    return(txdatabits);
}


struct iguana_ramchain *iguana_bundlemerge(struct iguana_info *coin,void *ptrs[],int32_t n,struct iguana_bundle *bp)
{
    struct iguana_ramchain *ramchain = 0;
    return(ramchain);
}

int32_t iguana_ramchainsave(struct iguana_info *coin,struct iguana_ramchain *ramchain,struct iguana_bundle *bp,int32_t n)
{
    printf("ramchainsave.%s %d[%d]\n",coin->symbol,bp->hdrsi,n);
    return(0);
}

void iguana_ramchainpurge(struct iguana_info *coin,struct iguana_ramchain *ramchain)
{
    
}

int32_t iguana_bundlesaveHT(struct iguana_info *coin,struct iguana_bundle *bp) // helper thread
{
    void *ptrs[IGUANA_MAXBUNDLESIZE]; uint32_t inds[IGUANA_MAXBUNDLESIZE][2]; struct iguana_fileitem *dir;
    struct iguana_bundle *itembp; int32_t addrind,bundlei,finished,fileind,i,j,num,flag,numdirs=0;
    struct iguana_txdatabits txdatabits; struct iguana_ramchain *ramchain;
    memset(ptrs,0,sizeof(ptrs));
    memset(inds,0,sizeof(inds));
    flag = 0;
    for (i=0; i<bp->n && i<coin->chain->bundlesize; i++)
    {
        if ( bp->blocks[i] != 0 )
        {
            txdatabits = bp->blocks[i]->txdatabits;
            if ( memcmp(bp->blocks[i]->hash2.bytes,coin->chain->genesis_hashdata,sizeof(bits256)) == 0 )
                ptrs[i] = coin->chain->genesis_hashdata, flag++;
            else if ( (ptrs[i]= iguana_peerfileptr(coin,txdatabits,1)) != 0 )
                flag++;
            else printf("peerfileptr[%d] (%d %d %d %d) null bp.%p %d\n",i,txdatabits.addrind,txdatabits.filecount,txdatabits.fpos,txdatabits.datalen,bp,bp->hdrsi);
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
        printf(">>>>>>>>> start MERGE numdirs.%d i.%d flag.%d\n",numdirs,i,flag);
        if ( (ramchain= iguana_bundlemerge(coin,ptrs,i,bp)) != 0 )
        {
            iguana_ramchainsave(coin,ramchain,bp,i);
            iguana_ramchainpurge(coin,ramchain);
        }
        for (j=0; j<numdirs; j++)
        {
            finished = 0;
            if ( (dir= iguana_peerdirptr(coin,&num,inds[j][0],inds[j][1],1)) != 0 )
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
                    iguana_peerfileclose(coin,inds[j][0],inds[j][1]);
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


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

#define uthash_malloc(size) iguana_memalloc(mem,size,1)
#define uthash_free iguana_stub

#include "iguana777.h"
void iguana_stub(void *ptr,int size) { printf("uthash_free ptr.%p %d\n",ptr,size); }

#define iguana_hashfind(hashtable,key,keylen) iguana_hashset(hashtable,0,key,keylen,-1)

struct iguana_kvitem *iguana_hashset(struct iguana_kvitem *hashtable,struct iguana_memspace *mem,void *key,int32_t keylen,int32_t itemind)
{
    struct iguana_kvitem *ptr = 0; int32_t allocsize;
    HASH_FIND(hh,hashtable,key,keylen,ptr);
    if ( ptr == 0 && itemind >= 0 )
    {
        allocsize = (int32_t)(sizeof(*ptr));
        if ( mem != 0 )
            ptr = iguana_memalloc(mem,allocsize,1);
        if ( ptr == 0 )
            printf("fatal alloc error in hashset\n"), exit(-1);
        //printf("ptr.%p allocsize.%d key.%p keylen.%d itemind.%d\n",ptr,allocsize,key,keylen,itemind);
        ptr->hh.itemind = itemind;
        HASH_ADD_KEYPTR(hh,hashtable,key,keylen,ptr);
    }
    if ( ptr != 0 )
    {
        struct iguana_kvitem *tmp;
        HASH_FIND(hh,hashtable,key,keylen,tmp);
        char str[65];
        if ( tmp != ptr )
            printf("%s itemind.%d search error %p != %p\n",init_hexbytes_noT(str,key,keylen),itemind,ptr,tmp);
        // else printf("added.(%s) height.%d %p\n",str,itemind,ptr);
    }
    return(ptr);
}

struct iguana_txdatabits iguana_calctxidbits(uint32_t addrind,uint32_t filecount,long fpos,int32_t datalen)
{
    struct iguana_txdatabits bits;
    if ( sizeof(bits) != 8 )
        printf("illegal bits size.%ld\n",sizeof(bits)), exit(-1);
    if ( (bits.addrind= addrind) != addrind )
        printf("iguana_txidbits: addrind overflow.%d\n",addrind), exit(-1);
    if ( (bits.filecount= filecount) != filecount )
        printf("iguana_txidbits: filecount overflow.%d\n",filecount), exit(-1);
    if ( (bits.fpos= fpos) != fpos )
        printf("iguana_txidbits: fpos overflow.%ld\n",fpos), exit(-1);
    if ( (bits.datalen= datalen) != datalen )
        printf("iguana_txidbits: datalen overflow.%d\n",datalen), exit(-1);
    return(bits);
}

void iguana_peerfilename(struct iguana_info *coin,char *fname,uint32_t addrind,uint32_t filecount)
{
    sprintf(fname,"tmp/%s/peer%d.%d",coin->symbol,addrind,filecount);
}

void *iguana_txdataptr(struct iguana_info *coin,struct iguana_mappedptr *M,char *fname,struct iguana_txdatabits txdatabits)
{
    int32_t len; uint8_t *rawptr;
    if ( M->fileptr != 0 && M->allocsize >= (txdatabits.fpos + txdatabits.datalen + sizeof(uint32_t)) )
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
        } else printf("txdataptr: len.%d error %d (%d %d %d)\n",len,txdatabits.datalen,len == txdatabits.datalen,len > sizeof(struct iguana_rawblock),len < IGUANA_MAXPACKETSIZE);
    } //else printf("txdataptr.%s %p %ld vs %ld\n",M->fname,M->fileptr,M->allocsize,(txdatabits.fpos + txdatabits.datalen + sizeof(uint32_t)));
    return(0);
}

void *iguana_peerfileptr(struct iguana_info *coin,struct iguana_txdatabits txdatabits,int32_t createflag)
{
    char fname[512]; int32_t i,oldesti,oldest,duration,datalen,fpos; struct iguana_mappedptr *M = 0; void *ptr = 0;
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
            //printf("mapped.(%s) size.%ld %p\n",fname,(long)M->allocsize,ptr);
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
        else if ( marker == IGUANA_MARKER )
            printf("marker.%x vs %x: dirpos.%d num.%d -> %ld vs %ld\n",marker,IGUANA_MARKER,dirpos,*nump,dirpos + sizeof(uint32_t) * 4 + *nump * sizeof(struct iguana_fileitem),ftell(fp));
        fclose(fp);
    } else printf("cant open dir.(%s)\n",fname);
    return(0);
}

FILE *iguana_peerfilePT(struct iguana_info *coin,struct iguana_peer *addr,bits256 hash2,struct iguana_txdatabits **txdatabitsptrp,int32_t recvlen)
{
    char fname[512]; int32_t marker; uint32_t dirpos;
    *txdatabitsptrp = 0;
    if ( bits256_nonz(hash2) == 0 || addr->fp == 0 || ftell(addr->fp) > IGUANA_PEERFILESIZE-IGUANA_MAXPACKETSIZE || addr->numfilehash2 >= sizeof(addr->filehash2)/sizeof(*addr->filehash2) )
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
            iguana_flushQ(coin,addr);
            //fflush(addr->fp);
        }
        iguana_peerfilename(coin,fname,addr->addrind,++addr->filecount);
        addr->fp = fopen(fname,"wb");
        addr->numfilehash2 = 0;
    }
    addr->filehash2[addr->numfilehash2].hash2 = hash2;
    (*txdatabitsptrp) = &addr->filehash2[addr->numfilehash2].txdatabits;
    addr->numfilehash2++;
    return(addr->fp);
}

struct iguana_rawblock *iguana_ramchainptrs(struct iguana_txid **Tptrp,struct iguana_unspent **Uptrp,struct iguana_spend **Sptrp,struct iguana_pkhash **Pptrp,bits256 **externalTptrp,struct iguana_memspace *mem,struct iguana_rawblock *origtxdata)
{
    struct iguana_rawblock *txdata; int32_t allocsize,rwflag = (origtxdata != 0);
    iguana_memreset(mem);
    allocsize = (int32_t)(sizeof(*txdata) - sizeof(txdata->space) + ((origtxdata != 0) ? origtxdata->extralen : 0));
    mem->alignflag = 4;
    if ( (txdata = iguana_memalloc(mem,allocsize,0)) == 0 )
        return(0);
    //printf("rwflag.%d origtxdat.%p allocsize.%d extralen.%d T.%d U.%d S.%d P.%d\n",rwflag,origtxdata,allocsize,origtxdata->extralen,txdata->numtxids,txdata->numunspents,txdata->numspends,txdata->numpkinds);
    if ( origtxdata != 0 )
        memcpy(txdata,origtxdata,allocsize);
    *Tptrp = iguana_memalloc(mem,sizeof(**Tptrp) * txdata->numtxids,rwflag);
    *Uptrp = iguana_memalloc(mem,sizeof(**Uptrp) * txdata->numvouts,rwflag);
    *Sptrp = iguana_memalloc(mem,sizeof(**Sptrp) * txdata->numvins,rwflag);
    if ( externalTptrp != 0 )
    {
        *Pptrp = iguana_memalloc(mem,0,rwflag);
        externalTptrp = iguana_memalloc(mem,txdata->numexternaltxids * sizeof(**externalTptrp),rwflag);
    } else *Pptrp = iguana_memalloc(mem,sizeof(**Pptrp) * txdata->numpkinds,rwflag);
    return(txdata);
}

struct iguana_txdatabits iguana_ramchainPT(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_rawblock *origtxdata,struct iguana_block *block,struct iguana_msgtx *txarray,int32_t txn_count,uint8_t *data,int32_t recvlen)
{
    struct iguana_txid *T,*t; struct iguana_unspent *U,*u; struct iguana_spend *S,*s; struct iguana_pkhash *P;
    FILE *fp; long fpos;  bits256 *externalT; struct iguana_kvitem *txids,*pkhashes,*ptr;
    struct iguana_memspace *txmem,*hashmem; struct iguana_msgtx *tx; struct iguana_rawblock *txdata = 0;
    int32_t i,j,numvins,numvouts,numexternal,numpkinds,scriptlen,sequence,spend_unspentind,datalen;
    uint32_t txidind,unspentind,spendind,pkind; uint8_t *script,rmd160[20]; struct iguana_txdatabits txdatabits;
    txmem = &addr->TXDATA, hashmem = &addr->HASHMEM;
    txids = pkhashes = 0;
    memset(&txdatabits,0,sizeof(txdatabits));
    //printf("recvlen.%d txn_count.%d\n",recvlen,txn_count);
    if ( (txdata= iguana_ramchainptrs(&T,&U,&S,&P,0,txmem,origtxdata)) == 0 || T == 0 || U == 0 || S == 0 || P == 0 )
    {
        printf("fatal error getting txdataptrs\n");
        exit(-1);
        return(txdatabits);
    }
    txidind = unspentind = spendind = pkind = 0;
    for (i=numvouts=numpkinds=0; i<txn_count; i++,txidind++)
    {
        tx = &txarray[i];
        t = &T[txidind];
        t->txid = tx->txid, t->txidind = txidind, t->firstvout = unspentind, t->numvouts = tx->tx_out;
        iguana_hashset(txids,hashmem,t->txid.bytes,sizeof(bits256),txidind);
        for (j=0; j<tx->tx_out; j++,numvouts++,unspentind++)
        {
            u = &U[unspentind];
            script = tx->vouts[j].pk_script, scriptlen = tx->vouts[j].pk_scriptlen;
            iguana_calcrmd160(coin,rmd160,script,scriptlen,tx->txid);
            if ( (ptr= iguana_hashfind(pkhashes,rmd160,sizeof(rmd160))) == 0 )
            {
                memcpy(P[numpkinds].rmd160,rmd160,sizeof(rmd160));
                if ( (ptr= iguana_hashset(pkhashes,hashmem,P[numpkinds].rmd160,sizeof(P[numpkinds].rmd160),numpkinds)) == 0 )
                    printf("fatal error adding pkhash\n"), exit(-1);
                numpkinds++;
            }
            u->value = tx->vouts[j].value, u->txidind = txidind;
            u->pkind = ptr->hh.itemind;
            P[u->pkind].firstunspentind = unspentind;
            P[u->pkind].extraind = u->pkind;
            // prevunspentind requires having accts, so that waits for third pass
        }
    }
    if ( (txdata->numpkinds= numpkinds) > 0 )
        P = iguana_memalloc(txmem,sizeof(*P) * numpkinds,0);
    externalT = iguana_memalloc(txmem,0,1);
    txidind = 0;
    for (i=numvins=numexternal=0; i<txn_count; i++,txidind++)
    {
        tx = &txarray[i];
        t = &T[txidind];
        t->firstvin = spendind, t->numvins = tx->tx_in;
        for (j=0; j<tx->tx_in; j++,numvins++,spendind++)
        {
            script = tx->vins[j].script, scriptlen = tx->vins[j].scriptlen;
            s = &S[spendind];
            if ( (sequence= tx->vins[j].sequence) != (uint32_t)-1 )
                s->diffsequence = 1;
            spend_unspentind = -1;
            if ( (ptr= iguana_hashfind(txids,tx->vins[j].prev_hash.bytes,sizeof(bits256))) != 0 )
                spend_unspentind = ptr->hh.itemind;
            else
            {
                spend_unspentind = (txdata->numvouts + numexternal);
                externalT[numexternal++] = tx->vins[j].prev_hash;
            }
            if ( spend_unspentind >= 0 && spend_unspentind < (txdata->numvouts + numexternal) )
                s->unspentind = ((spend_unspentind << 16) | tx->vins[j].prev_vout);
            // prevspendind requires having accts, so that waits for third pass
        }
    }
    if ( numexternal > 0 )
    {
        if ( (txdata->numexternaltxids= numexternal) != numexternal )
            printf("txdataset: numexternal overflow %d\n",numexternal), exit(-1);
        externalT = iguana_memalloc(txmem,sizeof(*externalT) * numexternal,0);
    }
    datalen = (int32_t)txmem->used;
    if ( (txdata->datalen= datalen) != datalen )
        printf("txdataset: datalen overflow %d\n",datalen), exit(-1);
    if ( numvins != txdata->numvins || numvouts != txdata->numvouts || i != txdata->numtxids )
    {
        printf("counts mismatch: numvins %d != %d txdata->numvins || numvouts %d != %d txdata->numvouts || i %d != %d txdata->numtxids\n",numvins,txdata->numvins,numvouts,txdata->numvouts,i,txdata->numtxids);
        exit(-1);
        return(txdatabits);
    }
    if ( (fp= addr->fp) != 0 )
    {
        iguana_bits256sort(&T[0],txdata->numtxids,sizeof(*T));
        iguana_bits256sort(&P[0],txdata->numpkinds,sizeof(*P));
        fpos = ftell(addr->fp);
        txdatabits = iguana_calctxidbits(addr->addrind,addr->filecount,fpos,txdata->datalen);
        //printf("txdatabits.(%d %d %d %d) txdatalen.%d\n",txdatabits.addrind,txdatabits.filecount,txdatabits.fpos,txdatabits.datalen,txdata->datalen);
        if ( fp != 0 )
        {
            datalen = txdata->datalen;
            if ( datalen == txdata->datalen )
            {
                fwrite(&datalen,1,sizeof(datalen),fp);
                fwrite(txdata,1,datalen,fp);
                iguana_flushQ(coin,addr);
                //fflush(fp);
            }
        }
    }
    {
        static int32_t maxrecvlen,maxdatalen,maxhashmem; static double recvsum,datasum;
        recvsum += recvlen, datasum += txdata->datalen;
        if ( recvlen > maxrecvlen )
            printf("[%.3f] %.0f/%.0f maxrecvlen %d -> %d\n",recvsum/datasum,recvsum,datasum,maxrecvlen,recvlen), maxrecvlen = recvlen;
        if ( txdata->datalen > maxdatalen )
            printf("[%.3f] %.0f/%.0f maxdatalen %d -> %d\n",recvsum/datasum,recvsum,datasum,maxdatalen,txdata->datalen), maxdatalen = txdata->datalen;
        if ( hashmem->used > maxhashmem )
            printf("[%.3f] %.0f/%.0f maxhashmem %d -> %ld\n",recvsum/datasum,recvsum,datasum,maxhashmem,hashmem->used), maxhashmem = (int32_t)hashmem->used;
        if ( (rand() % 10000) == 0 )
            printf("[%.3f] %.0f/%.0f recvlen vs datalen T.%ld U.%ld S.%ld P.%ld\n",recvsum/datasum,recvsum,datasum,sizeof(*T),sizeof(*U),sizeof(*S),sizeof(*P));
    }
    memcpy(origtxdata,txdata,sizeof(*txdata)+txdata->extralen);
    //printf("ret txdatabits.(%d %d %d %d) datalen.%d\n",txdatabits.addrind,txdatabits.filecount,txdatabits.fpos,txdatabits.datalen,txdata->datalen);
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
            } //else printf("cant get peerdirptr.(%d %d)\n",inds[j][0],inds[j][1]);
        }
    }
    else
    {
        printf(">>>>> bundlesaveHT error: numdirs.%d i.%d flag.%d\n",numdirs,i,flag);
        bp->emitfinish = 0;
    }
    return(flag);
}

// two passes to check data size
int32_t iguana_rwvin(int32_t rwflag,struct iguana_memspace *mem,uint8_t *serialized,struct iguana_msgvin *msg)
{
    int32_t len = 0;
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(msg->prev_hash),msg->prev_hash.bytes);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->prev_vout),&msg->prev_vout);
    //printf("vin.(%s) %d\n",bits256_str(msg->prev_hash),msg->prev_vout);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->scriptlen);
    if ( rwflag == 0 )
        msg->script = iguana_memalloc(mem,msg->scriptlen,1);
    len += iguana_rwmem(rwflag,&serialized[len],msg->scriptlen,msg->script);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->sequence),&msg->sequence);
    //int i; for (i=0; i<msg->scriptlen; i++)
    // printf("%02x ",msg->script[i]);
    //printf(" inscriptlen.%d, prevhash.%llx prev_vout.%d | ",msg->scriptlen,(long long)msg->prev_hash.txid,msg->prev_vout);
    return(len);
}

int32_t iguana_rwvout(int32_t rwflag,struct iguana_memspace *mem,uint8_t *serialized,struct iguana_msgvout *msg)
{
    int32_t len = 0;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->value),&msg->value);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->pk_scriptlen);
    if ( rwflag == 0 )
        msg->pk_script = iguana_memalloc(mem,msg->pk_scriptlen,1);
    len += iguana_rwmem(rwflag,&serialized[len],msg->pk_scriptlen,msg->pk_script);
    //printf("(%.8f scriptlen.%d) ",dstr(msg->value),msg->pk_scriptlen);
    //int i; for (i=0; i<msg->pk_scriptlen; i++)
    //    printf("%02x",msg->pk_script[i]);
    //printf("\n");
    return(len);
}

int32_t iguana_rwtx(int32_t rwflag,struct iguana_memspace *mem,uint8_t *serialized,struct iguana_msgtx *msg,int32_t maxsize,bits256 *txidp,int32_t hastimestamp)
{
    int32_t i,len = 0; uint8_t *txstart = serialized; char txidstr[65]; uint32_t timestamp;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->version),&msg->version);
    if ( hastimestamp != 0 )
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(timestamp),&timestamp);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->tx_in);
    //printf("version.%d ",msg->version);
    if ( msg->tx_in > 0 && msg->tx_out*100 < maxsize )
    {
        if ( rwflag == 0 )
            msg->vins = iguana_memalloc(mem,msg->tx_in * sizeof(*msg->vins),1);
        for (i=0; i<msg->tx_in; i++)
            len += iguana_rwvin(rwflag,mem,&serialized[len],&msg->vins[i]);
        //printf("numvins.%d\n",msg->tx_in);
    }
    else
    {
        printf("invalid tx_in.%d\n",msg->tx_in);
        return(-1);
    }
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->tx_out);
    if ( msg->tx_out > 0 && msg->tx_out*32 < maxsize )
    {
        //printf("numvouts.%d ",msg->tx_out);
        if ( rwflag == 0 )
            msg->vouts = iguana_memalloc(mem,msg->tx_out * sizeof(*msg->vouts),1);
        for (i=0; i<msg->tx_out; i++)
            len += iguana_rwvout(rwflag,mem,&serialized[len],&msg->vouts[i]);
    }
    else
    {
        printf("invalid tx_out.%d\n",msg->tx_out);
        return(-1);
    }
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->lock_time),&msg->lock_time);
    *txidp = bits256_doublesha256(txidstr,txstart,len);
    msg->allocsize = len;
    return(len);
}

int32_t iguana_gentxarray(struct iguana_info *coin,struct iguana_memspace *mem,struct iguana_rawblock *txdata,struct iguana_block *block,int32_t *lenp,uint8_t *data,int32_t recvlen)
{
    struct iguana_msgtx *tx; bits256 hash2; struct iguana_msgblock msg; int32_t i,n,len,numvouts,numvins;
    memset(&msg,0,sizeof(msg));
    len = iguana_rwblock(0,&hash2,data,&msg);
    iguana_convblock(block,&msg,hash2,-1);
    memset(txdata,0,sizeof(*txdata));
    txdata->hash2 = block->hash2;
    txdata->prev_block = block->prev_block;
    tx = iguana_memalloc(mem,msg.txn_count*sizeof(*tx),1);
    for (i=numvins=numvouts=0; i<msg.txn_count; i++)
    {
        if ( (n= iguana_rwtx(0,mem,&data[len],&tx[i],recvlen - len,&tx[i].txid,coin->chain->hastimestamp)) < 0 )
            break;
        numvouts += tx[i].tx_out;
        numvins += tx[i].tx_in;
        len += n;
    }
    if ( coin->chain->hastimestamp != 0 && len != recvlen && data[len] == (recvlen - len - 1) )
    {
        //printf("\n>>>>>>>>>>> len.%d vs recvlen.%d [%d]\n",len,recvlen,data[len]);
        memcpy(txdata->space,&data[len],recvlen-len);
        len += (recvlen - len);
        if ( (txdata->extralen= (recvlen - len)) != 0 )
            printf("gentxarray: extralen overflow %d\n",recvlen - len), exit(-1);
    } else txdata->extralen = 0;
    if ( (txdata->recvlen= len) != len )
        printf("gentxarray: recvlen overflow %d\n",len), exit(-1);
    if ( (txdata->numtxids= msg.txn_count) != msg.txn_count )
        printf("gentxarray: numtxids overflow %d\n",msg.txn_count), exit(-1);
    if ( (txdata->numvouts= numvouts) != numvouts )
        printf("gentxarray: numvouts overflow %d\n",numvouts), exit(-1);
    if ( (txdata->numvins= numvins) != numvins )
        printf("gentxarray: numvins overflow %d\n",numvins), exit(-1);
    return(len);
}

struct iguana_bundlereq *iguana_bundlereq(struct iguana_info *coin,struct iguana_peer *addr,int32_t type,int32_t datalen)
{
    struct iguana_bundlereq *req; int32_t allocsize;
    allocsize = (uint32_t)sizeof(*req) + datalen;
    req = mycalloc(type,1,allocsize);
    req->allocsize = allocsize;
    req->datalen = datalen;
    req->addr = addr;
    req->coin = coin;
    req->type = type;
    return(req);
}

// iguana_*MPT -> is passed memory pointers it must make sure is free, PT means it runs from peer thread
void iguana_gottxidsMPT(struct iguana_info *coin,struct iguana_peer *addr,bits256 *txids,int32_t n)
{
    struct iguana_bundlereq *req;
    printf("got %d txids from %s\n",n,addr->ipaddr);
    req = iguana_bundlereq(coin,addr,'T',0);
    req->hashes = txids, req->n = n;
    queue_enqueue("bundlesQ",&coin->bundlesQ,&req->DL,0);
}

void iguana_gotunconfirmedMPT(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_msgtx *tx,uint8_t *data,int32_t datalen)
{
    struct iguana_bundlereq *req;
    char str[65]; bits256_str(str,tx->txid);
    printf("%s unconfirmed.%s\n",addr->ipaddr,str);
    req = iguana_bundlereq(coin,addr,'U',datalen);
    req->datalen = datalen;
    memcpy(req->serialized,data,datalen);
    //iguana_freetx(tx,1);
    queue_enqueue("bundlesQ",&coin->bundlesQ,&req->DL,0);
}

void iguana_gotblockMPT(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_rawblock *txdata,struct iguana_block *block,struct iguana_msgtx *txarray,uint8_t *data,int32_t recvlen)
{
    struct iguana_bundlereq *req; int32_t i; struct iguana_txdatabits *txdatabitsptr,txdatabits;
    if ( 0 )
    {
        for (i=0; i<txdata->space[0]; i++)
            if ( txdata->space[i] != 0 )
                break;
        if ( i != txdata->space[0] )
        {
            for (i=0; i<txdata->space[0]; i++)
                printf("%02x ",txdata->space[i]);
            printf("extra\n");
        }
    }
    memset(&txdatabits,0,sizeof(txdatabits));
    req = iguana_bundlereq(coin,addr,'B',0);
    if ( addr != 0 )
    {
        if ( addr->pendblocks > 0 )
            addr->pendblocks--;
        addr->lastblockrecv = (uint32_t)time(NULL);
        addr->recvblocks += 1.;
        addr->recvtotal += recvlen;
        addr->fp = iguana_peerfilePT(coin,addr,txdata->hash2,&txdatabitsptr,recvlen);
        txdatabits = iguana_ramchainPT(coin,addr,txdata,block,txarray,txdata->numtxids,data,recvlen);
        //printf("iguana_ramchainPT returned txdatabits.(%d %d %d %d) vs %d\n",txdatabits.addrind,txdatabits.filecount,txdatabits.fpos,txdatabits.datalen,txdata->datalen);
        if ( txdatabits.datalen == txdata->datalen && txdatabits.filecount != 0 )
        {
            req->datalen = txdata->datalen;
            if ( txdatabitsptr != 0 )
                (*txdatabitsptr) = txdatabits;
            else printf("unexpected null txdatabitsptr\n"), getchar();
        } else printf("txdatabits.datalen overflow %d vs %d or zero filecount.%d\n",txdata->datalen,txdatabits.datalen,txdatabits.filecount), getchar();
    }
    coin->recvcount++;
    coin->recvtime = (uint32_t)time(NULL);
    req->block = *block;
    req->txdatabits = txdatabits;
    req->block.txn_count = req->numtx = txdata->numtxids;
    queue_enqueue("bundlesQ",&coin->bundlesQ,&req->DL,0);
}

void iguana_gotheadersMPT(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_block *blocks,int32_t n)
{
    struct iguana_bundlereq *req;
    if ( addr != 0 )
    {
        addr->recvhdrs++;
        if ( addr->pendhdrs > 0 )
            addr->pendhdrs--;
        //printf("%s blocks[%d] ht.%d gotheaders pend.%d %.0f\n",addr->ipaddr,n,blocks[0].height,addr->pendhdrs,milliseconds());
    }
    req = iguana_bundlereq(coin,addr,'H',0);
    req->blocks = blocks, req->n = n;
    queue_enqueue("bundlesQ",&coin->bundlesQ,&req->DL,0);
}

void iguana_gotblockhashesMPT(struct iguana_info *coin,struct iguana_peer *addr,bits256 *blockhashes,int32_t n)
{
    struct iguana_bundlereq *req;
    if ( addr != 0 )
    {
        addr->recvhdrs++;
        if ( addr->pendhdrs > 0 )
            addr->pendhdrs--;
    }
    req = iguana_bundlereq(coin,addr,'S',0);
    req->hashes = blockhashes, req->n = n;
    //printf("bundlesQ blockhashes.%p[%d]\n",blockhashes,n);
    queue_enqueue("bundlesQ",&coin->bundlesQ,&req->DL,0);
}

int32_t iguana_helpertask(FILE *fp,struct iguana_helper *ptr)
{
    struct iguana_info *coin; struct iguana_peer *addr;
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
            if ( ptr->bp != 0 )
                iguana_bundlesaveHT(coin,ptr->bp);
            if ( coin->estsize > coin->MAXRECVCACHE*.9 && coin->MAXBUNDLES > _IGUANA_MAXBUNDLES )
                coin->MAXBUNDLES--;
            else if ( coin->activebundles >= coin->MAXBUNDLES && coin->estsize < coin->MAXRECVCACHE*.5 )
                coin->MAXBUNDLES++;
            coin->numemitted++;
        }
    }
   /* if ( bp->type == 'Q' )
    {
        req = (struct iguana_bundlereq *)ptr;
        //printf("START.%p save tmp txdata %p [%d].%d datalen.%d %p\n",req,req->argbp,req->argbp!=0?req->argbp->hdrsi:-1,req->argbundlei,req->datalen,req->data);
        if ( fp != 0 )
        {
            if ( fwrite(req->data,1,req->datalen,fp) != req->datalen )
                printf("error writing [%d].%d datalen.%d\n",req->argbp!=0?req->argbp->hdrsi:-1,req->argbundlei,req->datalen);
        }
        //Tx_freed++;
        //Tx_freesize += req->allocsize;
        if ( req->data != 0 )
            myfree(req->data,req->datalen);
        if ( req->blocks != 0 )
            myfree(req->blocks,sizeof(*req->blocks));
        myfree(req,req->allocsize);
    }
    else if ( bp->type == 'E' )
    {
        fflush(fp);
        //myallocated(0,0);
        //iguana_emittxdata(bp->coin,bp);
        //myallocated(0,0);
    }
    else
    {
        printf("iguana_helper: unsupported type.%c %d %p\n",bp->type,bp->type,bp);
    }*/
    return(0);
}

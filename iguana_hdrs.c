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

void iguana_queuehdrs(struct iguana_info *coin,int32_t height,bits256 hash2,int32_t forceflag)
{
    char hashstr[65];
    if ( memcmp(bits256_zero.bytes,hash2.bytes,sizeof(hash2)) == 0 )
    {
        printf("trying to queue null hash\n");
        getchar();
    }
    if ( (forceflag != 0 && height > coin->blocks.hwmheight-IGUANA_HDRSCOUNT) || (height/IGUANA_HDRSCOUNT) > (coin->R.topheight/IGUANA_HDRSCOUNT) )
    {
        printf("queue hdrs height.%d %s\n",height,bits256_str(hash2));
        coin->R.pendingtopheight = coin->R.topheight;
        coin->R.pendingtopstart = (uint32_t)time(NULL);
        init_hexbytes_noT(hashstr,hash2.bytes,sizeof(hash2));
        queue_enqueue("hdrsQ",&coin->R.hdrsQ,queueitem(hashstr),1);
    }
}

void iguana_addcheckpoint(struct iguana_info *coin,int32_t height,bits256 hash2)
{
    int32_t checkpointi;
    if ( (checkpointi= (height / IGUANA_HDRSCOUNT)) >= coin->R.numcheckpoints || checkpointi < 0 )
        return;
    coin->R.checkpoints[checkpointi].hash2 = hash2;
    coin->R.checkpoints[checkpointi].height = (checkpointi * IGUANA_HDRSCOUNT);
}

int32_t iguana_checkpoint(struct iguana_info *coin,bits256 hash2)
{
    int32_t checkpointi;
    for (checkpointi=0; checkpointi<coin->R.numcheckpoints; checkpointi++)
        if ( memcmp(&coin->R.checkpoints[checkpointi].hash2,&hash2,sizeof(hash2)) == 0 )
            return(coin->R.checkpoints[checkpointi].height + 1);
    return(-1);
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
        for (height=0; height<coin->blocks.hwmheight; height+=IGUANA_HDRSCOUNT)
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
    while ( fgets(line,sizeof(line),fp) > 0 && m < IGUANA_MAXPEERS )
    {
        j = (int32_t)strlen(line) - 1;
        line[j] = 0;
        printf("parse line.(%s)\n",line);
        if ( iter == 0 )
        {
            addr = &coin->peers.active[m++];
            iguana_initpeer(coin,addr,(uint32_t)calc_ipbits(line));
            //printf("call initpeer.(%s)\n",addr->ipaddr);
            iguana_launch("connection",iguana_startconnection,addr,IGUANA_CONNTHREAD);
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
                    printf("add checkpoint.%d (%s)\n",height,bits256_str(hash2));
                    iguana_addcheckpoint(coin,height,hash2);
                    //iguana_queuehdrs(coin,height,hash2,1);
                }
            }
        }
    }
}

int32_t iguana_processhdrs(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_block *blocks,int32_t n)
{
    int32_t i,flag=0,startheight = -1,height = -1; struct iguana_block space,*block;
    startheight = iguana_checkpoint(coin,blocks[0].prev_block);
    if ( startheight >= 0 )
    {
        //memset(&coin->R.checkpoints[startheight/IGUANA_HDRSCOUNT].hash2,0,sizeof(bits256));
        printf("GOT CHECKPOINT.%d\n",startheight);
    }
    else if ( (block= iguana_findblock(coin,&space,blocks[0].prev_block)) != 0 )
        startheight = block->height+1;
    else if ( startheight < 0 )
    {
        printf("error matching headers (%s) %s\n",addr->ipaddr,bits256_str(blocks[0].hash2));
        return(-1);
    }
    if ( startheight >= 0 )
    {
        printf("%s received headers %d [%d] %s\n",addr->ipaddr,startheight,n,bits256_str(blocks[0].hash2));
        if ( startheight+n < coin->blocks.hwmheight )
            return(-1);
        for (i=0; i<n; i++)
        {
            if ( (height= startheight+i) < coin->blocks.hwmheight )
                continue;
            if ( (block= iguana_findblock(coin,&space,blocks[i].hash2)) == 0 || height > coin->blocks.hwmheight )
            {
                if ( (height= iguana_addblock(coin,blocks[i].hash2,&blocks[i])) > 0 )
                {
                    iguana_gotdata(coin,0,blocks[i].height,blocks[i].hash2);
                    flag++;
                }
            } else printf("height.%d:%d %s block.%p flag.%d\n",height,blocks[i].height,bits256_str(blocks[i].hash2),block,flag);
        }
        if ( flag != 0 )
        {
            iguana_queuehdrs(coin,blocks[n-1].height,blocks[n-1].hash2,1);
           //iguana_lookahead(coin,&hash2,coin->blocks.hwmheight + 1);
        }
    }
    return(flag);
}

void iguana_gotblockhashesM(struct iguana_info *coin,struct iguana_peer *addr,bits256 *hashes,int32_t n)
{
    int32_t i,height;
    //portable_mutex_lock(&coin->blocks.mutex);
    for (i=0; i<n; i++)
    {
        height = iguana_height(coin,hashes[i]);
        printf("%s.ht%d ",bits256_str(hashes[i]),height);
        iguana_gotdata(coin,addr,height,hashes[i]);
    }
    printf("got %d hashes from %s\n",n,addr->ipaddr);
    myfree(hashes,n * sizeof(*hashes));
    //portable_mutex_unlock(&coin->blocks.mutex);
}

void iguana_gotheaders(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_block *blocks,int32_t n)
{
    addr->lastrequest = bits256_zero;
    addr->recvhdrs++;
    if ( addr->pendhdrs > 0 )
        addr->pendhdrs--;
    coin->R.lasthdrtime = (uint32_t)time(NULL);
    portable_mutex_lock(&coin->blocks.mutex);
    iguana_processhdrs(coin,addr,blocks,n);
    portable_mutex_unlock(&coin->blocks.mutex);
}

int32_t iguana_updatehdrs(struct iguana_info *coin)
{
    bits256 hash2; int32_t height,checkpointi;
    if ( iguana_needhdrs(coin) == 0 )
        return(0);
    if ( 0 && coin->R.pendingtopheight == 0 )
    {
        for (checkpointi=coin->blocks.hwmheight/IGUANA_HDRSCOUNT; checkpointi<coin->R.numcheckpoints; checkpointi++)
            if ( memcmp(bits256_zero.bytes,coin->R.checkpoints[checkpointi].hash2.bytes,sizeof(coin->R.checkpoints[checkpointi])) != 0 )
                iguana_queuehdrs(coin,coin->R.checkpoints[checkpointi].height,coin->R.checkpoints[checkpointi].hash2,1);
        coin->R.pendingtopheight = 1;
        printf("issued initial gethdrs from %d\n",(coin->blocks.hwmheight/IGUANA_HDRSCOUNT)*IGUANA_HDRSCOUNT); //getchar();
    }
    if ( coin->R.topheight < coin->blocks.hwmheight )
        coin->R.topheight = coin->blocks.hwmheight;
    if ( coin->R.topheight == 0 || coin->R.topheight >= coin->R.pendingtopheight+IGUANA_HDRSCOUNT  || time(NULL) > (coin->R.lasthdrtime + 10) )
    {
        if ( coin->R.pendingtopheight != coin->R.topheight )
        {
            height = (coin->R.topheight/IGUANA_HDRSCOUNT) * IGUANA_HDRSCOUNT;
            hash2 = coin->R.checkpoints[height / IGUANA_HDRSCOUNT].hash2;
            if ( memcmp(bits256_zero.bytes,hash2.bytes,sizeof(hash2)) == 0 )
                hash2 = iguana_blockhash(coin,height);
            printf("request new header %d vs %d %u %s\n",height,coin->R.topheight,coin->R.pendingtopstart,bits256_str(hash2));
        }
        else
        {
            hash2 = coin->blocks.hwmchain;
            height = iguana_height(coin,hash2);
            printf("hwmchain request new header %d vs %d %u\n",coin->R.pendingtopheight,coin->R.topheight,coin->R.pendingtopstart);
        }
        coin->R.lasthdrtime = (uint32_t)time(NULL);
        if ( memcmp(bits256_zero.bytes,hash2.bytes,sizeof(hash2)) != 0 )
        {
            iguana_queuehdrs(coin,height,hash2,1);
            return(1);
        }
    }
    if ( coin->newhdrs != 0 )
    {
        coin->newhdrs = 0;
        height = coin->blocks.hwmheight;
        iguana_lookahead(coin,&hash2,height + 1);
        if ( coin->blocks.hwmheight > height )
            return(1);
    }
    return(0);
}

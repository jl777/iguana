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
//#include "../SuperNET_API/plugins/includes/uthash.h"
//#include "../SuperNET_API/plugins/includes/utlist.h"

portable_mutex_t MEMmutex;

long myallocated(uint8_t type,long change)
{
    static int32_t Total_allocated,HWM_allocated,Type_allocated[256];
    int32_t i; long total = 0; char buf[2049];
    buf[0] = 0;
    if ( type == 0 && change == 0 )
    {
        for (i=0; i<256; i++)
        {
            if ( Type_allocated[i] != 0 )
            {
                total += Type_allocated[i];
                sprintf(buf+strlen(buf),"(%c %ld) ",i,(long)Type_allocated[i]);
            }
        }
        sprintf(buf + strlen(buf),"-> total %ld %s",total,mbstr(total));
        printf("%s\n",buf);
    }
    else
    {
        Type_allocated[type] += change;
        Total_allocated += change;
        if ( Total_allocated > HWM_allocated )
        {
            printf("HWM allocated %ld %s\n",Total_allocated,mbstr(Total_allocated));
            HWM_allocated = Total_allocated * 1.5;
        }
    }
    return(total);
}

void *mycalloc(uint8_t type,int32_t n,long itemsize)
{
    struct allocitem *item; uint64_t allocsize = ((uint64_t)n * itemsize);
    if ( type == 0 && n == 0 && itemsize == 0 )
    {
        portable_mutex_init(&MEMmutex);
        myfree(mycalloc('t',1024,1024 * 32),1024*1024*32);
        return(0);
    }
    portable_mutex_lock(&MEMmutex);
    myallocated(type,allocsize);
    while ( (item= calloc(1,sizeof(struct allocitem) + allocsize)) == 0 )
    {
        printf("mycalloc: need to wait for memory.(%d,%ld) %s to be available\n",n,itemsize,mbstr(allocsize));
        sleep(1);
    }
    //printf("calloc origptr.%p retptr.%p size.%ld\n",item,(void *)(long)item + sizeof(*item),allocsize);
    item->allocsize = (uint32_t)allocsize;
    item->type = type;
    portable_mutex_unlock(&MEMmutex);
    return((void *)(long)item + sizeof(*item));
}

void *queueitem(char *str)
{
    struct queueitem *item; uint32_t n,allocsize; char *data; uint8_t type = 'y';
    portable_mutex_lock(&MEMmutex);
    n = (uint32_t)strlen(str) + 1;
    allocsize = (uint32_t)(sizeof(struct queueitem) + n);
    myallocated(type,allocsize);
    while ( (item= calloc(1,allocsize)) == 0 )
    {
        printf("queueitem: need to wait for memory.(%d,%ld) %s to be available\n",n,(long)sizeof(*item),mbstr(allocsize));
        sleep(1);
    }
    item->allocsize = (uint32_t)allocsize;
    item->type = type;
    data = (void *)((uint64_t)item + sizeof(*item));
    memcpy(data,str,n);
    //printf("(%c) queueitem.%p itemdata.%p n.%d allocsize.%d\n",type,item,data,n,allocsize);
    portable_mutex_unlock(&MEMmutex);
    return(data);
}

void _myfree(uint8_t type,uint32_t origallocsize,void *origptr,uint32_t allocsize)
{
    portable_mutex_lock(&MEMmutex);
    if ( allocsize == origallocsize )
    {
        myallocated(type,-allocsize);
       // Type_allocated[type & 0xff] -= allocsize;
       // Total_allocated -= allocsize;
        //printf("myfree.%p size.%d %d type %x\n",origptr,allocsize,origallocsize,type);
        free(origptr);
    }
    else
    {
        printf("myfree size error %d vs %d at %p\n",allocsize,origallocsize,origptr);
        getchar();
    }
    portable_mutex_unlock(&MEMmutex);
}

void myfree(void *_ptr,long allocsize)
{
    struct allocitem *item = (void *)((long)_ptr - sizeof(struct allocitem));
    _myfree(item->type,item->allocsize,item,(uint32_t)allocsize);
}

void free_queueitem(void *itemdata)
{
    struct queueitem *item = (void *)((long)itemdata - sizeof(struct queueitem));
    //printf("freeq item.%p itemdata.%p size.%d\n",item,itemdata,item->allocsize);
    _myfree(item->type,item->allocsize,item,item->allocsize);
}

void *myrealloc(uint8_t type,void *oldptr,long oldsize,long newsize)
{
    void *newptr;
    newptr = mycalloc(type,1,newsize);
    //printf("newptr.%p type.%c oldsize.%ld newsize.%ld\n",newptr,type,oldsize,newsize);
    if ( oldptr != 0 )
    {
        memcpy(newptr,oldptr,oldsize < newsize ? oldsize : newsize);
        myfree(oldptr,oldsize);
    }
    return(newptr);
}

static uint64_t _align16(uint64_t ptrval) { if ( (ptrval & 15) != 0 ) ptrval += 16 - (ptrval & 15); return(ptrval); }

void *myaligned_alloc(uint64_t allocsize)
{
    void *ptr,*realptr; uint64_t tmp;
    realptr = mycalloc('A',1,(long)(allocsize + 16 + sizeof(realptr)));
    tmp = _align16((long)realptr + sizeof(ptr));
    memcpy(&ptr,&tmp,sizeof(ptr));
    memcpy((void *)((long)ptr - sizeof(realptr)),&realptr,sizeof(realptr));
    //printf("aligned_alloc(%llu) realptr.%p -> ptr.%p, diff.%ld\n",(long long)allocsize,realptr,ptr,((long)ptr - (long)realptr));
    return(ptr);
}

int32_t myaligned_free(void *ptr,long size)
{
    void *realptr;
    long diff;
    if ( ((long)ptr & 0xf) != 0 )
    {
        printf("misaligned ptr.%p being aligned_free\n",ptr);
        return(-1);
    }
    memcpy(&realptr,(void *)((long)ptr - sizeof(realptr)),sizeof(realptr));
    diff = ((long)ptr - (long)realptr);
    if ( diff < (long)sizeof(ptr) || diff > 32 )
    {
        printf("ptr %p and realptr %p too far apart %ld\n",ptr,realptr,diff);
        return(-2);
    }
    //printf("aligned_free: ptr %p -> realptr %p %ld\n",ptr,realptr,diff);
    myfree(realptr,size + 16 + sizeof(realptr));
    return(0);
}

void lock_queue(queue_t *queue)
{
    if ( queue->initflag == 0 )
    {
        portable_mutex_init(&queue->mutex);
        queue->initflag = 1;
    }
	portable_mutex_lock(&queue->mutex);
}

void queue_enqueue(char *name,queue_t *queue,struct queueitem *origitem,int32_t offsetflag)
{
    struct queueitem *item;
    if ( queue->list == 0 && name != 0 && name[0] != 0 )
        strcpy(queue->name,name);//,sizeof(queue->name));
    if ( origitem == 0 )
    {
        printf("FATAL type error: queueing empty value\n");//, getchar();
        return;
    }
    lock_queue(queue);
    item = (struct queueitem *)((long)origitem - offsetflag*sizeof(struct queueitem));
    DL_APPEND(queue->list,item);
    portable_mutex_unlock(&queue->mutex);
    //printf("queue_enqueue name.(%s) origitem.%p append.%p list.%p\n",name,origitem,item,queue->list);
}

void *queue_dequeue(queue_t *queue,int32_t offsetflag)
{
    struct queueitem *item = 0;
    lock_queue(queue);
    if ( queue->list != 0 )
    {
        item = queue->list;
        DL_DELETE(queue->list,item);
        //printf("queue_dequeue name.(%s) dequeue.%p list.%p\n",queue->name,item,queue->list);
    }
	portable_mutex_unlock(&queue->mutex);
    if ( item != 0 && offsetflag != 0 )
        return((void *)((long)item + sizeof(struct queueitem)));
    else return(item);
}

void *queue_delete(queue_t *queue,struct queueitem *copy,int32_t copysize,int32_t freeitem)
{
    struct queueitem *item = 0;
    lock_queue(queue);
    if ( queue->list != 0 )
    {
        DL_FOREACH(queue->list,item)
        {
            if ( item == copy || memcmp((void *)((long)item + sizeof(struct queueitem)),(void *)((long)item + sizeof(struct queueitem)),copysize) == 0 )
            {
                DL_DELETE(queue->list,item);
                portable_mutex_unlock(&queue->mutex);
                printf("name.(%s) deleted item.%p list.%p\n",queue->name,item,queue->list);
                if ( freeitem != 0 )
                    myfree(item,copysize);
                return(item);
            }
        }
    }
	portable_mutex_unlock(&queue->mutex);
    return(0);
}

void *queue_free(queue_t *queue)
{
    struct queueitem *item = 0;
    lock_queue(queue);
    if ( queue->list != 0 )
    {
        DL_FOREACH(queue->list,item)
        {
            DL_DELETE(queue->list,item);
            myfree(item,sizeof(struct queueitem));
        }
        //printf("name.(%s) dequeue.%p list.%p\n",queue->name,item,queue->list);
    }
	portable_mutex_unlock(&queue->mutex);
    return(0);
}

void *queue_clone(queue_t *clone,queue_t *queue,int32_t size)
{
    struct queueitem *ptr,*item = 0;
    lock_queue(queue);
    if ( queue->list != 0 )
    {
        DL_FOREACH(queue->list,item)
        {
            ptr = mycalloc('c',1,sizeof(*ptr));
            memcpy(ptr,item,size);
            queue_enqueue(queue->name,clone,ptr,0);
        }
        //printf("name.(%s) dequeue.%p list.%p\n",queue->name,item,queue->list);
    }
	portable_mutex_unlock(&queue->mutex);
    return(0);
}

int32_t queue_size(queue_t *queue)
{
    int32_t count = 0;
    struct queueitem *tmp;
    lock_queue(queue);
    DL_COUNT(queue->list,tmp,count);
    portable_mutex_unlock(&queue->mutex);
	return count;
}

bits256 bits256_doublesha256(char *hashstr,uint8_t *data,int32_t datalen)
{
    bits256 hash,hash2; int32_t i;
    vcalc_sha256(0,hash.bytes,data,datalen);
    vcalc_sha256(0,hash2.bytes,hash.bytes,sizeof(hash));
    for (i=0; i<sizeof(hash); i++)
        hash.bytes[i] = hash2.bytes[sizeof(hash) - 1 - i];
    if ( hashstr != 0 )
        init_hexbytes_noT(hashstr,hash.bytes,sizeof(hash));
    return(hash);
}

char *bits256_str(bits256 x)
{
    static char hexstr[65];
    init_hexbytes_noT(hexstr,x.bytes,sizeof(x));
    return(hexstr);
}

char *bits256_str2(bits256 x)
{
    static char hexstr[65];
    init_hexbytes_noT(hexstr,x.bytes,sizeof(x));
    return(hexstr);
}

char *bits256_lstr(bits256 x)
{
    static char hexstr[65]; bits256 revx; int32_t i;
    for (i=0; i<32; i++)
        revx.bytes[i] = x.bytes[31-i];
    init_hexbytes_noT(hexstr,revx.bytes,sizeof(revx));
    return(hexstr);
}

bits256 bits256_add(bits256 a,bits256 b)
{
    int32_t i; bits256 sum; uint64_t x,carry = 0;
    memset(sum.bytes,0,sizeof(sum));
    for (i=0; i<4; i++)
    {
        x = a.ulongs[i] + b.ulongs[i];
        sum.ulongs[i] = (x + carry);
        if ( x < a.ulongs[i] || x < b.ulongs[i] )
            carry = 1;
        else carry = 0;
    }
    return(sum);
}

int32_t bits256_cmp(bits256 a,bits256 b)
{
    int32_t i;
    for (i=0; i<4; i++)
    {
        if ( a.ulongs[i] > b.ulongs[i] )
            return(1);
        else if ( a.ulongs[i] < b.ulongs[i] )
            return(-1);
    }
    return(0);
}

int32_t bits256_nonz(bits256 a)
{
    static const bits256 z;
    return(memcmp(a.bytes,z.bytes,sizeof(a)) != 0);
}

bits256 bits256_lshift(bits256 x)
{
    int32_t i,carry,prevcarry = 0; uint64_t mask = (1LL << 63);
    for (i=0; i<4; i++)
    {
        carry = ((mask & x.ulongs[i]) != 0);
        x.ulongs[i] = (x.ulongs[i] << 1) | prevcarry;
        prevcarry = carry;
    }
    return(x);
}

bits256 bits256_from_compact(uint32_t c)
{
	uint32_t nbytes,nbits,i; bits256 x;
    memset(x.bytes,0,sizeof(x));
    nbytes = (c >> 24) & 0xFF;
    nbits = (8 * (nbytes - 3));
    x.ulongs[0] = c & 0xFFFFFF;
    for (i=0; i<nbits; i++) // horrible inefficient
        x = bits256_lshift(x);
    return(x);
}

void calc_OP_HASH160(char hexstr[41],uint8_t hash160[20],char *pubkey)
{
    uint8_t sha256[32],buf[4096]; int32_t len;
    len = (int32_t)strlen(pubkey)/2;
    if ( len > sizeof(buf) )
    {
        printf("calc_OP_HASH160 overflow len.%d vs %d\n",len,(int32_t)sizeof(buf));
        return;
    }
    decode_hex(buf,len,pubkey);
    vcalc_sha256(0,sha256,buf,len);
    calc_rmd160(0,hash160,sha256,sizeof(sha256));
    if ( 0 )
    {
        int i;
        for (i=0; i<20; i++)
            printf("%02x",hash160[i]);
        printf("<- (%s)\n",pubkey);
    }
    if ( hexstr != 0 )
        init_hexbytes_noT(hexstr,hash160,20);
}

double _dxblend(double *destp,double val,double decay)
{
    double oldval;
	if ( (oldval = *destp) != 0. )
		return((oldval * decay) + ((1. - decay) * val));
	else return(val);
}

double dxblend(double *destp,double val,double decay)
{
	double newval,slope;
	if ( isnan(*destp) != 0 )
		*destp = 0.;
	if ( isnan(val) != 0 )
		return(0.);
	if ( *destp == 0 )
	{
		*destp = val;
		return(0);
	}
	newval = _dxblend(destp,val,decay);
	if ( newval < SMALLVAL && newval > -SMALLVAL )
	{
		// non-zero marker for actual values close to or even equal to zero
		if ( newval < 0. )
			newval = -SMALLVAL;
		else newval = SMALLVAL;
	}
	if ( *destp != 0. && newval != 0. )
		slope = (newval - *destp);
	else slope = 0.;
	*destp = newval;
	return(slope);
}

/*queue_t TerminateQ; int32_t TerminateQ_queued;
void iguana_terminator(void *arg)
{
    struct iguana_thread *t; uint32_t lastdisp = 0; int32_t terminated = 0;
    printf("iguana_terminator\n");
    while ( 1 )
    {
        if ( (t= queue_dequeue(&TerminateQ,0)) != 0 )
        {
            printf("terminate.%p\n",t);
            iguana_terminate(t);
            terminated++;
            continue;
        }
        sleep(1);
        if ( time(NULL) > lastdisp+60 )
        {
            lastdisp = (uint32_t)time(NULL);
            printf("TerminateQ %d terminated of %d queued\n",terminated,TerminateQ_queued);
        }
    }
}*/

static queue_t TerminateQ; static uint32_t Launched[8],Terminated[8];

int32_t iguana_numthreads(int32_t mask)
{
    int32_t i,sum = 0;
    for (i=0; i<8; i++)
        if ( ((1 << i) & mask) != 0 )
            sum += (Launched[i] - Terminated[i]);
    return(sum);
}

void iguana_launcher(void *ptr)
{
    struct iguana_thread *t = ptr;
    t->funcp(t->arg);
    Terminated[t->type % (sizeof(Terminated)/sizeof(*Terminated))]++;
    queue_enqueue("TerminateQ",&TerminateQ,&t->DL,0);
}

void iguana_terminate(struct iguana_thread *t)
{
    int32_t retval;
    retval = pthread_join(t->handle,NULL);
    if ( retval != 0 )
        printf("error.%d terminating t.%p thread.%s\n",retval,t,t->name);
    myfree(t,sizeof(*t));
}

struct iguana_thread *iguana_launch(char *name,iguana_func funcp,void *arg,uint8_t type)
{
    int32_t retval; struct iguana_thread *t;
    t = mycalloc('Z',1,sizeof(*t));
    strcpy(t->name,name);
    t->funcp = funcp;
    t->arg = arg;
    t->type = (type % (sizeof(Terminated)/sizeof(*Terminated)));
    Launched[t->type]++;
    retval = pthread_create(&t->handle,NULL,(void *)iguana_launcher,(void *)t);
    if ( retval != 0 )
        printf("error launching %s\n",t->name);
    while ( (t= queue_dequeue(&TerminateQ,0)) != 0 )
    {
        if ( (rand() % 100000) == 0 )
            printf("terminated.%d launched.%d terminate.%p\n",Terminated[t->type],Launched[t->type],t);
        iguana_terminate(t);
    }
    return(t);
}

char hexbyte(int32_t c)
{
    c &= 0xf;
    if ( c < 10 )
        return('0'+c);
    else if ( c < 16 )
        return('a'+c-10);
    else return(0);
}

int32_t _unhex(char c)
{
    if ( c >= '0' && c <= '9' )
        return(c - '0');
    else if ( c >= 'a' && c <= 'f' )
        return(c - 'a' + 10);
    else if ( c >= 'A' && c <= 'F' )
        return(c - 'A' + 10);
    return(-1);
}

int32_t is_hexstr(char *str)
{
    int32_t i;
    if ( str == 0 || str[0] == 0 )
        return(0);
    for (i=0; str[i]!=0; i++)
        if ( _unhex(str[i]) < 0 )
            return(0);
    return(1);
}

int32_t unhex(char c)
{
    int32_t hex;
    if ( (hex= _unhex(c)) < 0 )
    {
        //printf("unhex: illegal hexchar.(%c)\n",c);
    }
    return(hex);
}

unsigned char _decode_hex(char *hex) { return((unhex(hex[0])<<4) | unhex(hex[1])); }

int32_t decode_hex(unsigned char *bytes,int32_t n,char *hex)
{
    int32_t adjust,i = 0;
    //printf("decode.(%s)\n",hex);
    if ( is_hexstr(hex) == 0 )
    {
        memset(bytes,0,n);
        return(n);
    }
    if ( n == 0 || (hex[n*2+1] == 0 && hex[n*2] != 0) )
    {
        bytes[0] = unhex(hex[0]);
        printf("decode_hex n.%d hex[0] (%c) -> %d hex.(%s) [n*2+1: %d] [n*2: %d %c] len.%ld\n",n,hex[0],bytes[0],hex,hex[n*2+1],hex[n*2],hex[n*2],(long)strlen(hex));
#ifdef __APPLE__
        getchar();
#endif
        bytes++;
        hex++;
        adjust = 1;
    } else adjust = 0;
    if ( n > 0 )
    {
        for (i=0; i<n; i++)
            bytes[i] = _decode_hex(&hex[i*2]);
    }
    //bytes[i] = 0;
    return(n + adjust);
}

int32_t init_hexbytes_noT(char *hexbytes,unsigned char *message,long len)
{
    int32_t i;
    if ( len == 0 )
    {
        hexbytes[0] = 0;
        return(1);
    }
    for (i=0; i<len; i++)
    {
        hexbytes[i*2] = hexbyte((message[i]>>4) & 0xf);
        hexbytes[i*2 + 1] = hexbyte(message[i] & 0xf);
        //printf("i.%d (%02x) [%c%c]\n",i,message[i],hexbytes[i*2],hexbytes[i*2+1]);
    }
    hexbytes[len*2] = 0;
    //printf("len.%ld\n",len*2+1);
    return((int32_t)len*2+1);
}

void touppercase(char *str)
{
    int32_t i;
    if ( str == 0 || str[0] == 0 )
        return;
    for (i=0; str[i]!=0; i++)
        str[i] = toupper(((int32_t)str[i]));
}

long _stripwhite(char *buf,int accept)
{
    int32_t i,j,c;
    if ( buf == 0 || buf[0] == 0 )
        return(0);
    for (i=j=0; buf[i]!=0; i++)
    {
        buf[j] = c = buf[i];
        if ( c == accept || (c != ' ' && c != '\n' && c != '\r' && c != '\t' && c != '\b') )
            j++;
    }
    buf[j] = 0;
    return(j);
}

char *clonestr(char *str)
{
    char *clone;
    if ( str == 0 || str[0] == 0 )
    {
        printf("warning cloning nullstr.%p\n",str);
#ifdef __APPLE__
        while ( 1 ) sleep(1);
#endif
        str = (char *)"<nullstr>";
    }
    clone = (char *)malloc(strlen(str)+16);
    strcpy(clone,str);
    return(clone);
}

int32_t myatoi(char *str,int32_t range)
{
    long x; char *ptr;
    x = strtol(str,&ptr,10);
    if ( range != 0 && x >= range )
        x = (range - 1);
    return((int32_t)x);
}

int32_t safecopy(char *dest,char *src,long len)
{
    int32_t i = -1;
    if ( dest != 0 )
        memset(dest,0,len);
    if ( src != 0 && dest != 0 )
    {
        for (i=0; i<len&&src[i]!=0; i++)
            dest[i] = src[i];
        if ( i == len )
        {
            printf("safecopy: %s too long %ld\n",src,len);
#ifdef __APPLE__
            //getchar();
#endif
            return(-1);
        }
        dest[i] = 0;
    }
    return(i);
}

void escape_code(char *escaped,char *str)
{
    int32_t i,j,c; char esc[16];
    for (i=j=0; str[i]!=0; i++)
    {
        if ( ((c= str[i]) >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') )
            escaped[j++] = c;
        else
        {
            sprintf(esc,"%%%02X",c);
            //sprintf(esc,"\\\\%c",c);
            strcpy(escaped + j,esc);
            j += strlen(esc);
        }
    }
    escaped[j] = 0;
    //printf("escape_code: (%s) -> (%s)\n",str,escaped);
}

int32_t is_zeroes(char *str)
{
    int32_t i;
    if ( str == 0 || str[0] == 0 )
        return(1);
    for (i=0; str[i]!=0; i++)
        if ( str[i] != '0' )
            return(0);
    return(1);
}

int64_t conv_floatstr(char *numstr)
{
    double val,corr;
    val = atof(numstr);
    corr = (val < 0.) ? -0.50000000001 : 0.50000000001;
    return((int64_t)(val * SATOSHIDEN + corr));
}

int32_t has_backslash(char *str)
{
    int32_t i;
    if ( str == 0 || str[0] == 0 )
        return(0);
    for (i=0; str[i]!=0; i++)
        if ( str[i] == '\\' )
            return(1);
    return(0);
}

int32_t conv_date(int32_t *secondsp,char *date)
{
    char origdate[64],tmpdate[64]; int32_t year,month,day,hour,min,sec,len;
    strcpy(origdate,date), strcpy(tmpdate,date), tmpdate[8 + 2] = 0;
    year = myatoi(tmpdate,3000), month = myatoi(tmpdate+5,13), day = myatoi(tmpdate+8,32);
    *secondsp = 0;
    if ( (len= (int32_t)strlen(date)) <= 10 )
        hour = min = sec = 0;
    if ( len >= 18 )
    {
        tmpdate[11 + 2] = 0, tmpdate[14 + 2] = 0, tmpdate[17 + 2] = 0;
        hour = myatoi(tmpdate+11,25), min = myatoi(tmpdate + 14,61), sec = myatoi(tmpdate+17,61);
        if ( hour >= 0 && hour < 24 && min >= 0 && min < 60 && sec >= 0 && sec < 60 )
            *secondsp = (3600*hour + 60*min + sec);
        else printf("ERROR: seconds.%d %d %d %d, len.%d\n",*secondsp,hour,min,sec,len);
    }
    sprintf(origdate,"%d-%02d-%02d",year,month,day); //2015-07-25T22:34:31Z
    if ( strcmp(tmpdate,origdate) != 0 )
    {
        printf("conv_date date conversion error (%s) -> (%s)\n",origdate,date);
        return(-1);
    }
    return((year * 10000) + (month * 100) + day);
}

static double _kb(double n) { return(n / 1024.); }
static double _mb(double n) { return(n / (1024.*1024.)); }
static double _gb(double n) { return(n / (1024.*1024.*1024.)); }

char *mbstr(double n)
{
	static char str[100];
	if ( n < 1024*1024*10 )
		sprintf(str,"%.3fkb",_kb(n));
	else if ( n < 1024*1024*1024 )
		sprintf(str,"%.1fMB",_mb(n));
	else
		sprintf(str,"%.2fGB",_gb(n));
	return(str);
}

// from tweetnacl
void randombytes(unsigned char *x,long xlen)
{
    static int fd = -1;
    int32_t i;
    if (fd == -1) {
        for (;;) {
            fd = open("/dev/urandom",O_RDONLY);
            if (fd != -1) break;
            sleep(1);
        }
    }
    while (xlen > 0) {
        if (xlen < 1048576) i = (int32_t)xlen; else i = 1048576;
        i = (int32_t)read(fd,x,i);
        if (i < 1) {
            sleep(1);
            continue;
        }
        if ( 0 )
        {
            int32_t j;
            for (j=0; j<i; j++)
                printf("%02x ",x[j]);
            printf("-> %p\n",x);
        }
        x += i;
        xlen -= i;
    }
}

double milliseconds()
{
    struct timeval tv; double millis;
    gettimeofday(&tv,NULL);
    millis = ((double)tv.tv_sec * 1000. + (double)tv.tv_usec / 1000.);
    //printf("tv_sec.%ld usec.%d %f\n",tv.tv_sec,tv.tv_usec,millis);
    return(millis);
}

//void msleep(uint32_t millis) { usleep(millis * 1000); }

void *iguana_loadfile(char *fname,char **bufp,int64_t *lenp,int64_t *allocsizep)
{
    FILE *fp;
    int64_t  filesize,buflen = *allocsizep;
    char *buf = *bufp;
    *lenp = 0;
    PostMessage("loadfile.(%s)\n",fname);
    if ( (fp= fopen(iguana_compatible_path(fname),"rb")) != 0 )
    {
        fseek(fp,0,SEEK_END);
        filesize = ftell(fp);
        if ( filesize == 0 )
        {
            fclose(fp);
            *lenp = 0;
            PostMessage("loadfile.(%s) no filesize\n",fname);
            return(0);
        }
        if ( filesize > buflen-1 )
        {
            *allocsizep = filesize+1;
            *bufp = buf = realloc(buf,(long)*allocsizep);
        }
        rewind(fp);
        if ( buf == 0 )
            printf("Null buf ???\n");
        else
        {
            if ( fread(buf,1,(long)filesize,fp) != (unsigned long)filesize )
                printf("error reading filesize.%ld\n",(long)filesize);
            buf[filesize] = 0;
        }
        fclose(fp);
        *lenp = filesize;
    }
    PostMessage("done loadfile.(%s) size.%lld\n",fname,(long long)*lenp);
    return(buf);
}

void *iguana_filestr(int64_t *allocsizep,char *fname)
{
    int64_t filesize = 0; char *buf = 0;
    *allocsizep = 0;
    return(iguana_loadfile(fname,&buf,&filesize,allocsizep));
}

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

#include "includes/cJSON.h"

char *HTMLheader =
"<!DOCTYPE HTML> \
<html style=\"overflow-y:scroll;-webkit-user-select: text\"> \
<head> \
<meta http-equiv=\"Pragma\" content=\"no-cache\"> \
<meta http-equiv=\"Expires\" content=\"-1\"> \
<title>iguana</title> \
<script src=\"jquery-2.1.4.min.js\" type=\"text/javascript\"></script> \
<link rel=\"stylesheet\" href=\"css/bootstrap.css\" type=\"text/css\"> \
\
</head> \
<body data-custom-load=\"true\" data-name=\"iguana\" data-tools=\"pnacl newlib glibc clang-newlib mac\" data-configs=\"Debug Release\" data-path=\"{tc}/{config}\">";

// <a href="./iguana/link?field=val">Link</a>

char *HTMLfooter =
"<script type=\"text/javascript\" src=\"js/util.js\"></script> \
\
<script type=\"text/javascript\" src=\"common.js\"></script> \
<script type=\"text/javascript\" src=\"example.js\"></script> \
\
<script src=\"js/bootstrap.js\" type=\"text/javascript\"></script> \
<script src=\"js/api.js\" type=\"text/javascript\" charset=\"utf-8\"></script> \
<script src=\"js/methods.js\" type=\"text/javascript\" charset=\"utf-8\"></script> \
<script src=\"js/sites.js\" type=\"text/javascript\" charset=\"utf-8\"></script> \
<script src=\"js/settings.js\" type=\"text/javascript\" charset=\"utf-8\"></script> \
<script src=\"js/jay.min.js\"></script> \
<script src=\"js/jay.ext.js\"></script> \
\
</body> \
</html>";

#define HTML_EMIT(str)  if ( (str) != 0 && (str)[0] != 0 ) strcpy(&retbuf[size],str), size += (int32_t)strlen(str)

char *iguana_rpc(char *agent,cJSON *json,char *data,int32_t datalen)
{
    //printf("agent.(%s) json.(%s) data[%d] %s\n",agent,jprint(json,0),datalen,data!=0?data:"");
    if ( data == 0 )
        return(iguana_JSON(jprint(json,0)));
    else return(iguana_JSON(data));
}

void iguana_urldecode(char *str)
{
    int32_t a,b,c; char *dest = str;
    while ( (c= *str) != 0 )
    {
        if ( c == '%' && (a= str[1]) != 0 && (b= str[2]) != 0 )
            *dest++ = (unhex(a)<<4) | unhex(b);
        else *dest++ = c;
    }
    *dest = 0;
}

char *iguana_htmlget(char *path)
{
    char *ramchain_parser(struct iguana_agent *agent,struct iguana_info *coin,char *method,cJSON *json);
    bits256 hash2; int32_t height; char jsonreq[1024];
    printf("GETCHECK.(%s)\n",path);
    if ( strncmp(path,"/ramchain/",strlen("/ramchain/")) == 0 )
    {
        path += strlen("/ramchain/");
        if ( strncmp(path,"height/",strlen("height/")) == 0 )
        {
            height = atoi(path + strlen("height/"));
            sprintf(jsonreq,"{\"agent\":\"ramchain\",\"method\":\"block\",\"height\":%d}",height);
            return(ramchain_parser(0,0,"block",cJSON_Parse(jsonreq)));
        }
        else if ( strncmp(path,"blockhash/",strlen("blockhash/")) == 0 )
        {
            decode_hex(hash2.bytes,sizeof(hash2),path + strlen("blockhash/"));
            char str[65]; printf("ramchain blockhash.%s\n",bits256_str(str,hash2));
            sprintf(jsonreq,"{\"agent\":\"ramchain\",\"method\":\"block\",\"hash\":\"%s\"}",str);
            return(ramchain_parser(0,0,"block",cJSON_Parse(jsonreq)));
        }
        else if ( strncmp(path,"txid/",strlen("txid/")) == 0 )
        {
            decode_hex(hash2.bytes,sizeof(hash2),path + strlen("txid/"));
            char str[65]; printf("ramchain txid.%s\n",bits256_str(str,hash2));
            sprintf(jsonreq,"{\"agent\":\"ramchain\",\"method\":\"tx\",\"txid\":\"%s\"}",str);
            return(ramchain_parser(0,0,"tx",cJSON_Parse(jsonreq)));
        }
        return(clonestr("{\"error\":\"ramchain unknown request\"}"));
    } else printf("no match to (%s)\n",path);
    return(0);
}

char *iguana_rpcparse(char *jsonstr)
{
    cJSON *json = 0; int32_t i,n,datalen,postflag = 0;
    char *key,*reststr,*str,*retstr,*data = 0,*value,*agent = "SuperNET";
    //printf("rpcparse.(%s)\n",jsonstr);
    if ( strncmp("POST",jsonstr,4) == 0 )
        jsonstr += 6, postflag = 1;
    else if ( strncmp("GET",jsonstr,3) == 0 )
    {
        jsonstr += 4;
        str = 0;
        if ( (str= iguana_htmlget(jsonstr)) == 0 && (reststr= strstr(jsonstr,"Referer: http://127.0.0.1:7778")) != 0 )
        {
            reststr += strlen("Referer: http://127.0.0.1:7778");
            str = iguana_htmlget(reststr);
        }
        if ( str != 0 )
        {
            json = cJSON_CreateObject();
            jaddstr(json,"result",str);
            str = cJSON_Print(json);
            free_json(json);
            return(str);
        }
        jsonstr++;
    }
    else return(0);
    n = (int32_t)strlen(jsonstr);
    for (i=0; i<n; i++)
        if ( jsonstr[i] == '?' )
            break;
    if ( i == n )
    {
        printf("no url\n");
        return(0);
    }
    if ( i > 0 )
    {
        jsonstr[i] = 0;
        agent = jsonstr;
        jsonstr += i;
    }
    jsonstr++;
    json = cJSON_CreateObject();
    jaddstr(json,"agent",agent);
    while ( 1 )
    {
        n = (int32_t)strlen(jsonstr);
        key = jsonstr;
        value = 0;
        for (i=0; i<n; i++)
        {
            if ( jsonstr[i] == ' ' || jsonstr[i] == '&' )
                break;
            else if ( jsonstr[i] == '=' )
            {
                if ( value != 0 )
                {
                    printf("parse error.(%s)\n",jsonstr);
                    free_json(json);
                    return(0);
                }
                jsonstr[i] = 0;
                value = &jsonstr[++i];
            }
        }
        if ( value == 0 )
            value = "";
        jsonstr += i;
        if ( jsonstr[0] == ' ' )
        {
            jsonstr[0] = 0;
            jsonstr++;
            if ( key != 0 && key[0] != 0 )
                jaddstr(json,key,value);
            //printf("{%s:%s}\n",key,value);
            break;
        }
        jsonstr[0] = 0;
        jsonstr++;
        if ( key != 0 && key[0] != 0 )
            jaddstr(json,key,value);
        //printf("{%s:%s}\n",key,value);
        if ( i == 0 )
            break;
    }
    n = (int32_t)strlen(jsonstr);
    datalen = 0;
    if ( postflag != 0 )
    {
        for (i=0; i<n; i++)
        {
            //printf("(%d) ",jsonstr[i]);
            if ( jsonstr[i] == '\n' || jsonstr[i] == '\r' )
            {
                //printf("[%s] cmp.%d\n",jsonstr+i+1,strncmp(jsonstr+i+1,"Content-Length:",strlen("Content-Length:")));
                if ( strncmp(jsonstr+i+1,"Content-Length:",strlen("Content-Length:")) == 0 )
                {
                    datalen = (int32_t)atoi(jsonstr + i + 1 + strlen("Content-Length:") + 1);
                    data = &jsonstr[n - datalen];
                    iguana_urldecode(data);
                    printf("post.(%s) (%c)\n",data,data[0]);
                }
            }
        }
    }
    retstr = iguana_rpc(agent,json,data,datalen);
    free_json(json);
    return(retstr);
    //printf("post.%d json.(%s) data[%d] %s\n",postflag,jprint(json,0),datalen,data!=0?data:"");
    //return(json);
}

int32_t iguana_htmlgen(char *retbuf,int32_t bufsize,char *result,char *error,cJSON *json,char *tabname)
{
    char *url = "http://127.0.0.1:7778";
    int i,j,m,size = 0,n,rows,cols; cJSON *array,*obj,*array2,*item;
    char formheader[512],formfooter[512],clickname[512],buf[512],fieldbuf[512],fieldindex[2],postjson[8192];
    char *disp,*fieldname,*button,*formname,*agent,*method;
    bufsize--;
    HTML_EMIT("<html> <head></head> <body> Result: <text>");
    HTML_EMIT(result);
    HTML_EMIT(error);
    HTML_EMIT("</text><br><br/>");
    formheader[0] = formfooter[0] = 0;
    if ( (array= jarray(&n,json,"forms")) != 0 )
    {
        for (i=0; i<n; i++)
        {
            item = jitem(array,i);
            //printf("FORM[%d] of %d %s\n",i,n,jprint(item,0));
            // {"forms":[{"name":"block","agent":"ramchain","fields":[{"disp":"height of block","field":"height","cols":10,"rows":1},{"disp":"blockhash","field":"hash","cols":65,"rows":1}]}]}
            if ( (formname= jstr(item,"name")) == 0 )
                formname = "form";
            sprintf(clickname,"%s%d_%s",tabname,i,formname);
            if ( (button= jstr(item,"button")) == 0 )
                button = formname;
            sprintf(buf,"<script> function click_%s()\n{\n",clickname);
            HTML_EMIT(buf);
            if ( (agent= jstr(item,"agent")) == 0 )
                agent = "iguana";
            if ( (method= jstr(item,"method")) == 0 )
                method = formname;
            sprintf(postjson,"%s",agent);
            //printf("form.%s button.%s [%s]\n",formname,button,postjson);
            if ( (array2= jarray(&m,item,"fields")) != 0 )
            {
                for (j=0; j<m; j++)
                {
                    obj = jitem(array2,j);
                    //printf("item[%d] -> (%s)\n",j,jprint(obj,0));
                    sprintf(fieldindex,"%c",'A'+j);
                    if ( (fieldname= jstr(obj,"field")) != 0 )
                    {
                        sprintf(buf,"%s = document.%s.%s.value;\n",fieldindex,formname,fieldname);
                        HTML_EMIT(buf);
                        //sprintf(postjson+strlen(postjson),",\"%s\":\"' + %s + '\"",fieldname,fieldindex);
                        sprintf(postjson+strlen(postjson),"/%s/' + %s + '",fieldname,fieldindex);
                    }
                }
                //strcat(postjson,"}");
                sprintf(&retbuf[size],"location.href = '%s/%s';\n}</script>\r\n",url,postjson), size += strlen(&retbuf[size]);
                sprintf(formheader,"<b>%s</b><form name=\"%s\" action=\"%s\" method=\"POST\" onsubmit=\"return submitForm(this);\"><table>",formname,formname,url);
                HTML_EMIT(formheader);
                for (j=0; j<m; j++)
                {
                    obj = jitem(array2,j);
                    rows = juint(json,"rows");
                    cols = juint(json,"cols");
                    if ( (fieldname= jstr(obj,"field")) == 0 )
                        sprintf(fieldbuf,"%s_%c",clickname,'A'+j), fieldname = fieldbuf;
                    if ( (disp= jstr(json,"disp")) == 0 )
                        disp = fieldname;
                    if ( rows == 0 && cols == 0 )
                        sprintf(buf,"<input type=\"text\" name=\"%s\"/>",fieldname);
                    else sprintf(buf,"<textarea cols=\"%d\" rows=\"%d\"  name=\"%s\"/></textarea>",cols,rows,fieldname);
                    sprintf(&retbuf[size],"<td>%s</td> <td> %s </td><br>\r\n",disp,buf), size += strlen(&retbuf[size]);
                }
                sprintf(formfooter,"<td colspan=\"2\"> <input type=\"button\" value=\"%s\" onclick=\"click_%s()\" /></td> </tr>\n</table></form><br/>",button,clickname);
                HTML_EMIT(formfooter);
            }
        }
    }
    HTML_EMIT("<br><br/>"); HTML_EMIT("</body></html>"); HTML_EMIT("<br><br/>");
    return((int32_t)strlen(retbuf));
}
#undef HTML_EMIT

char *iguana_htmlresponse(char *retbuf,int32_t bufsize,int32_t *remainsp,int32_t localaccess,char *retstr,int32_t freeflag)
{
    static char *html = "<html> <head></head> <body> %s </body> </html>";
    char *result=0,*error=0; int32_t n; cJSON *json;
    retbuf[0] = 0;
    /*if ( localaccess == 0 )
     sprintf(retbuf+strlen(retbuf),"Access-Control-Allow-Origin: *\r\n");
     else sprintf(retbuf+strlen(retbuf),"Access-Control-Allow-Origin: null\r\n");
     sprintf(retbuf+strlen(retbuf),"Access-Control-Allow-Credentials: true\r\n");
     sprintf(retbuf+strlen(retbuf),"Access-Control-Allow-Headers: Authorization, Content-Type\r\n");
     sprintf(retbuf+strlen(retbuf),"Access-Control-Allow-Methods: GET, POST\r\n");
     sprintf(retbuf+strlen(retbuf),"Cache-Control: no-cache, no-store, must-revalidate\r\n");
     sprintf(retbuf+strlen(retbuf),"Content-type: text/html\r\n");
     sprintf(retbuf+strlen(retbuf),"Content-Length: %d\r\n\r\n",n);*/
    sprintf(retbuf+strlen(retbuf),"<!DOCTYPE HTML>\n\r");
    n = (int32_t)strlen(retbuf);
    if ( (json= cJSON_Parse(retstr)) != 0 )
    {
        error = jstr(json,"error");
        if ( (result= jstr(json,"result")) != 0 )
        {
            jadd(json,"forms",cJSON_Parse("[{\"name\":\"block\",\"agent\":\"ramchain\",\"fields\":[{\"field\":\"height\",\"cols\":10,\"rows\":1}]},{\"name\":\"blockhash\",\"agent\":\"ramchain\",\"fields\":[{\"field\":\"blockhash\",\"cols\":65,\"rows\":1}]},{\"name\":\"txid\",\"agent\":\"ramchain\",\"fields\":[{\"field\":\"txid\",\"cols\":65,\"rows\":1}]}]"));
            printf("process.(%s)\n",jprint(json,0));
            n = iguana_htmlgen(&retbuf[n],bufsize-n,result,error,json,"ramchain");
        }
        free_json(json);
    }
    if ( n == 0 )
    {
        n = (int32_t)(strlen(html) + strlen(retstr) + 1);
        sprintf(retbuf+strlen(retbuf),html,retstr);
    }
    if ( freeflag != 0 )
        free(retstr);
    if ( n > bufsize )
    {
        printf("htmlresponse overflowed buffer[%d] with %d\n",bufsize,n);
        exit(-1);
    }
    *remainsp = n;
    return(retbuf);
}

void iguana_rpcloop(void *args)
{
    int32_t recvlen,bindsock,sock,remains,numsent,len; socklen_t clilen;
    char ipaddr[64],jsonbuf[8192],*buf,*retstr,*space;//,*retbuf; ,n,i,m
    struct sockaddr_in cli_addr; uint32_t ipbits,i,size = 1024*1024; uint16_t port;
    port = IGUANA_RPCPORT;//coin->chain->portrpc;
    bindsock = iguana_socket(1,"127.0.0.1",port);
    printf("iguana_rpcloop 127.0.0.1:%d bind sock.%d\n",port,bindsock);
    space = calloc(1,size);
    while ( bindsock >= 0 )
    {
        clilen = sizeof(cli_addr);
        printf("ACCEPT (%s:%d) on sock.%d\n","127.0.0.1",port,bindsock);
        sock = accept(bindsock,(struct sockaddr *)&cli_addr,&clilen);
        if ( sock < 0 )
        {
            printf("ERROR on accept usock.%d\n",sock);
            continue;
        }
        memcpy(&ipbits,&cli_addr.sin_addr.s_addr,sizeof(ipbits));
        expand_ipbits(ipaddr,ipbits);
        //printf("RPC.%d for %x (%s)\n",sock,ipbits,ipaddr);
        //printf("%p got.(%s) from %s | usock.%d ready.%u dead.%u\n",addr,H.command,addr->ipaddr,addr->usock,addr->ready,addr->dead);
        memset(jsonbuf,0,sizeof(jsonbuf));
        remains = (int32_t)(sizeof(jsonbuf) - 1);
        buf = jsonbuf;
        recvlen = 0;
        retstr = 0;
        while ( remains > 0 )
        {
            if ( (len= (int32_t)recv(sock,buf,remains,0)) < 0 )
            {
                if ( errno == EAGAIN )
                {
                    printf("EAGAIN for len %d, remains.%d\n",len,remains);
                    usleep(10000);
                }
                break;
            }
            else
            {
                if ( len > 0 )
                {
                    remains -= len;
                    recvlen += len;
                    buf = &buf[len];
                } else usleep(10000);
                //printf("got.(%s) %d remains.%d of total.%d\n",jsonbuf,recvlen,remains,len);
                retstr = iguana_rpcparse(jsonbuf);
                break;
            }
        }
        if ( retstr != 0 )
        {
            i = 0;
            retstr = iguana_htmlresponse(space,size,&remains,1,retstr,1);
            printf("RETBUF.(%s)\n",retstr);
            while ( remains > 0 )
            {
                if ( (numsent= (int32_t)send(sock,&retstr[i],remains,MSG_NOSIGNAL)) < 0 )
                {
                    if ( errno != EAGAIN && errno != EWOULDBLOCK )
                    {
                        printf("%s: %s numsent.%d vs remains.%d len.%d errno.%d (%s) usock.%d\n",retstr,ipaddr,numsent,remains,recvlen,errno,strerror(errno),sock);
                        break;
                    }
                }
                else if ( remains > 0 )
                {
                    remains -= numsent;
                    i += numsent;
                    if ( remains > 0 )
                        printf("iguana sent.%d remains.%d of len.%d\n",numsent,remains,recvlen);
                }
            }
            //free(retstr);
        }
        //printf("done response sock.%d\n",sock);
        close(sock);
    }
}
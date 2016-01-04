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

void iguana_bitmapbundle(uint8_t *rect,int32_t rowwidth,int32_t width,int32_t height,struct iguana_bundle *bp)
{
    int32_t x,y; uint8_t red,green,blue,*ptr; double frac,sum = 0.;
    if ( bp != 0 )
    {
        if ( bp->red == 0 )
            bp->red = rand(), bp->green = rand(), bp->blue = rand();
        red = bp->red, green = bp->green, blue = bp->blue;
        frac = (double)bp->n / (width * height);
        for (y=0; y<height; y++,rect+=rowwidth*3)
        {
            ptr = rect;
            for (x=0; x<width; x++,sum+=frac)
            {
                if ( bp->ipbits[(int32_t)sum] != 0 )
                    *ptr++ = red, *ptr++ = green, *ptr++ = blue;
                else *ptr++ = 0, *ptr++ = 0, *ptr++ = 0;
            }
        }
    }
}

struct iguana_bitmap *iguana_bitmapfind(char *name)
{
    struct iguana_info *coin; int32_t width,height,n,hdrsi,x,y;
    if ( (coin= iguana_coin(name)) != 0 )
    {
        strcpy(coin->screen.name,coin->symbol);
        coin->screen.amplitude = 255;
        coin->screen.width = IGUANA_WIDTH;
        coin->screen.height = IGUANA_HEIGHT;
        memset(coin->screen.data,0xff,sizeof(coin->screen.data));
        if ( coin->bundlescount > 0 )
        {
            n = 100;
            while ( n > 0 )
            {
                width = IGUANA_WIDTH / n;
                height = IGUANA_HEIGHT / n;
                //printf("n.%d -> (%d %d) rects.%d vs %d\n",n,width,height,width*height,coin->bundlescount);
                if ( width*height >= coin->bundlescount )
                    break;
                n--;
            }
            for (y=hdrsi=0; y<height; y++)
            {
                for (x=0; x<width; x++,hdrsi++)
                {
                    if ( hdrsi >= coin->bundlescount )
                        break;
                    iguana_bitmapbundle(&coin->screen.data[3*(y*coin->screen.width*n + x*n)],coin->screen.width,n,n,coin->bundles[hdrsi]);
                }
            }
        }
        return(&coin->screen);
    }
    return(0);
}

void iguana_bitmap(char *space,int32_t max,char *name)
{
    struct iguana_bitmap *rect; char pixel[64]; uint8_t *ptr; int32_t h,w,red,green,blue,x,y,n,len = 0;
    if ( name == 0 || name[0] == 0 || (rect= iguana_bitmapfind(name)) == 0 )
    {
        strcpy(space,"{\"name\":\"nobitmap\",\"amplitude\":222,\"width\":1,\"height\":1,\"pixels\":[222,0,22]}");
        //sprintf(space,"Content-type: text/standard\r\n");
        //sprintf(space+strlen(space),"Content-Length: %ld\r\n\r\n",strlen(buf));
        //strcpy(space,buf);
        //printf("bitmap.[%s]\n",space);
    }
    else
    {
        sprintf(space,"{\"name\":\"%s\",\"amplitude\":%u,\"width\":%d,\"height\":%d,\"pixels\":[",name,rect->amplitude,rect->width,rect->height), len = (int32_t)strlen(space);
        ptr = rect->data;
        h = rect->height, w = rect->width;
        for (y=0; y<h; y++)
        {
            for (x=0; x<w; x++)
            {
                red = *ptr++, green = *ptr++, blue = *ptr++;
                sprintf(pixel,"%u,%u,%u,",red,green,blue);
                n = (int32_t)strlen(pixel);
                memcpy(&space[len],pixel,n);
                len += n;
            }
        }
        space[len-1] = ']', space[len++] = '}', space[len++] = 0;
        //printf("BIGMAP.(%s)\n",space);
    }
}

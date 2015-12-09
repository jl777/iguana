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

void iguana_coinloop(void *arg)
{
    int32_t flag,i,n,m; uint32_t now,lastdisp = 0; struct iguana_info *coin,**coins = arg;
    n = (int32_t)(long)coins[0];
    coins++;
    printf("begin coinloop[%d]\n",n);
    coin = coins[0];
    iguana_possible_peer(coin,"127.0.0.1");
    while ( 1 )
    {
        flag = 0;
        for (i=0; i<n; i++)
        {
            if ( (coin= coins[i]) != 0 )
            {
                now = (uint32_t)time(NULL);
                if ( now > coin->lastpossible )
                    coin->lastpossible = iguana_possible_peer(coin,0); // tries to connect to new peers
                if ( now > coin->peers.lastmetrics+60 )
                    coin->peers.lastmetrics = iguana_updatemetrics(coin); // ranks peers
                flag += iguana_updatebundles(coin);
                if ( 0 && coin->blocks.parsedblocks < coin->blocks.hwmheight-coin->chain->minconfirms )
                {
                    if ( iguana_updateramchain(coin) != 0 )
                        iguana_syncs(coin), flag++; // merge ramchain fragments into full ramchain
                }
            }
        }
        if ( now > lastdisp+1 )
        {
            lastdisp = (uint32_t)now;
            for (i=m=0; i<coin->longestchain; i++)
                if ( iguana_havehash(coin,i) > 0 )
                    m++;
            printf("%s.%d: pend.%d/%d hash.%d/%d I.%d recv.%d/%d emit.%d HWM.%d parsed.%d |long.%d %.2f min\n",coin->symbol,flag,coin->numpendings,coin->hdrscount,coin->blocks.hashblocks,m,coin->blocks.issuedblocks,coin->blocks.recvblocks,coin->recvcount,coin->blocks.emitblocks,coin->blocks.hwmheight,coin->blocks.parsedblocks,coin->longestchain,(double)(time(NULL)-coin->starttime)/60.);
            if ( (rand() % 60) == 0 )
                myallocated();
        }
        if ( flag == 0 )
            usleep(5000);
    }
}

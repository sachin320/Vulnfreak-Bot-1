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

    embed.set_thumbnail(url="https://cdn.discordapp.com/attachments/799308817274896415/803128693294628914/2755bfa3d9fe1bd81b8ba67603a3f3e9-removebg-preview.png")
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
    embed.set_thumbnail(url="https://cdn.discordapp.com/attachments/799308817274896415/803128693294628914/2755bfa3d9fe1bd81b8ba67603a3f3e9-removebg-preview.png")
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



client.run('API_TOKEN')



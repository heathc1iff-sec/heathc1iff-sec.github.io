---
title: TryHackMe-Active Directory Basics
description: 'Red Teaming'
pubDate: 2024-04-06
image: /image/tryhackme.jpg
categories:
  - Documentation
tags:
  - Tryhackme
---

# <font style="color:rgb(31, 31, 31);">Brief</font>
<font style="color:rgb(14, 16, 26);">This room will take you through what phishing is, how it's performed, some valuable tools and why it's an essential part of a Red Team engagement. </font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">这个房间将带您了解什么是网络钓鱼、它是如何执行的、一些有价值的工具以及为什么它是红队参与的重要组成部分。</font>

<font style="color:rgb(14, 16, 26);">  
</font>

<font style="color:rgb(14, 16, 26);">Now it's time to move to the next task and receive your </font>**<font style="color:rgb(14, 16, 26);">Intro to</font>****<font style="color:rgb(14, 16, 26);"> </font>****<u><font style="color:rgb(14, 16, 26);">Phishing</font></u>****<font style="color:rgb(14, 16, 26);">!</font>**<font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">现在是时候进入下一个任务并接收您的网络钓鱼简介了！</font>

## <font style="color:rgb(235, 0, 55);">Answer the questions below  
</font><font style="color:rgb(235, 0, 55);">回答以下问题</font>
<font style="color:rgb(21, 28, 43);">I'm ready to learn!  
</font><font style="color:rgb(21, 28, 43);">我准备好学习了！</font>

# <font style="color:rgb(31, 31, 31);">Intro To Phishing Attacks</font>
<font style="color:rgb(14, 16, 26);">Before you learn what phishing is, you'll need to understand the term social engineering. Social engineering is the psychological manipulation of people into performing or divulging information by exploiting weaknesses in human nature. These "weaknesses" can be curiosity, jealously, greed and even kindness and the willingness to help someone.</font><font style="color:rgb(14, 16, 26);"> </font><u><font style="color:rgb(14, 16, 26);">Phishing</font></u><font style="color:rgb(14, 16, 26);"> </font><font style="color:rgb(14, 16, 26);">is a source of social engineering delivered through email to trick someone into either revealing personal information, credentials or even executing malicious code on their computer.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">在了解什么是网络钓鱼之前，您需要了解“社会工程”一词。社会工程是通过利用人性的弱点来对人们进行心理操纵，使其执行或泄露信息。这些“弱点”可以是好奇心、嫉妒、贪婪，甚至是善良和帮助某人的意愿。网络钓鱼是通过电子邮件传递的社会工程的来源，旨在诱骗某人泄露个人信息、凭据，甚至在他们的计算机上执行恶意代码。</font><font style="color:rgb(14, 16, 26);">  
</font>

<font style="color:rgb(14, 16, 26);">  
</font>

<font style="color:rgb(14, 16, 26);">These emails will usually appear to come from a trusted source, whether that's a person or a business. They include content that tries to tempt or trick people into downloading software, opening attachments, or following links to a bogus website.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">这些电子邮件通常看起来来自受信任的来源，无论是个人还是企业。它们包括试图引诱或诱骗人们下载软件、打开附件或点击虚假网站链接的内容。</font>

<font style="color:rgb(14, 16, 26);">  
</font>

<font style="color:rgb(14, 16, 26);">A term you'll come across and the type of phishing campaign a red team would participate in is </font>**<u><font style="color:rgb(14, 16, 26);">spear-phishing</font></u>****<font style="color:rgb(14, 16, 26);">,</font>**<font style="color:rgb(14, 16, 26);"> as with throwing a physical spear; you'd have a target to aim at, the same can be said with spear-phishing in that you're targeting an individual, business or organisation rather than just anybody as mass. This is an effective form of phishing for a red team engagement as they are bespoke to the target it makes them hard to detect by technology such as spam filters, antivirus and firewalls.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">您会遇到的一个术语以及红队将参与的网络钓鱼活动类型是鱼叉式网络钓鱼，就像投掷物理鱼叉一样;你会有一个目标，鱼叉式网络钓鱼也是如此，因为你的目标是个人、企业或组织，而不仅仅是任何人。对于红队参与来说，这是一种有效的网络钓鱼形式，因为它们是为目标定制的，这使得它们很难被垃圾邮件过滤器、防病毒软件和防火墙等技术检测到。</font><font style="color:rgb(14, 16, 26);">  
</font>

<font style="color:rgb(14, 16, 26);">  
</font>

<font style="color:rgb(14, 16, 26);">A red team could be contracted to solely carry out a phishing assessment to see whether a business is vulnerable to this type of attack or can also be part of a broader scale assessment and used to gain access to computer systems or services.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">可以与红队签订合同，专门进行网络钓鱼评估，以查看企业是否容易受到此类攻击，或者也可以成为更广泛评估的一部分，并用于访问计算机系统或服务。</font>

<font style="color:rgb(14, 16, 26);">  
</font>

<font style="color:rgb(14, 16, 26);">Some other methods of phishing through other mediums are smishing which is phishing through SMS messages, and vishing which is performed through phone calls.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">通过其他媒介进行网络钓鱼的其他一些方法是通过短信钓鱼，以及通过电话执行的网络钓鱼。</font>

<font style="color:rgb(14, 16, 26);">  
</font>

**<font style="color:rgb(14, 16, 26);">Example Scenario:</font>****<font style="color:rgb(14, 16, 26);"> </font>****<font style="color:rgb(14, 16, 26);">示例场景：</font>**<font style="color:rgb(14, 16, 26);">  
</font>

<font style="color:rgb(14, 16, 26);">  
</font>

<font style="color:rgb(14, 16, 26);">The below example scenario shows how an employee of a company could be tricked into revealing their credentials.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">下面的示例场景显示了如何诱骗公司员工泄露其凭据。</font>

<font style="color:rgb(14, 16, 26);">  
</font>

1) The attacker locates the physical location of the target business.  
1）攻击者定位目标企业的物理位置。

2) The attacker then looks for nearby food suppliers and discovers a company called **Ultimate Cookies!**  
2）攻击者随后寻找附近的食品供应商，并发现了一家名为Ultimate Cookies的公司！  


3) The Attacker registers the domain name **ultimate-cookies.thm**  
3）攻击者注册域名ultimate-cookies.thm

4) The attacker then crafts an email to their target, tempting them with an offer of receiving some free cookies if they sign up to the website. Because the victim has heard of this local company, they are more likely to trust it.  
4） 然后，攻击者会向他们的目标发送一封电子邮件，如果他们注册该网站，就会收到一些免费 cookie。因为受害者听说过这家当地公司，所以他们更有可能信任它。

5) The victim then follows the link in the email to the fake website created by the attacker and registers online. To keep things simple, the victim reuses the same password for all their online accounts.  
5） 然后，受害者按照电子邮件中的链接访问攻击者创建的虚假网站并在线注册。为简单起见，受害者对其所有在线帐户重复使用相同的密码。

6) The attacker now has the victim's email address and password and can log onto the victim's company email account. The attacker could now have access to private company information and also have somewhere to launch another phishing attack against other employees.  
6）攻击者现在拥有受害者的电子邮件地址和密码，可以登录受害者的公司电子邮件帐户。攻击者现在可以访问私人公司信息，也可以在某个地方对其他员工发起另一次网络钓鱼攻击。

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712328524869-d26aafc5-6857-4f6c-a670-4a8063fbac9f.png)

<font style="color:rgb(14, 16, 26);">  
</font>

<font style="color:rgb(14, 16, 26);">  
</font>

<font style="color:rgb(14, 16, 26);">Next, you'll learn what goes on in setting up the infrastructure for a red team phishing campaign.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">接下来，您将了解为红队网络钓鱼活动设置基础结构的过程。</font>

<font style="color:rgb(14, 16, 26);"></font>

## <font style="color:rgb(14, 16, 26);">答题</font>
#### <font style="color:rgb(21, 28, 43);">What type of psychological manipulation is phishing part of?  
</font><font style="color:rgb(21, 28, 43);">网络钓鱼属于哪种类型的心理操纵？</font>
<font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">social engineering</font>

#### <font style="color:rgb(21, 28, 43);">What type of phishing campaign do red teams get involved in?  
</font><font style="color:rgb(21, 28, 43);">红队参与什么类型的网络钓鱼活动？</font>
<font style="color:rgb(21, 28, 43);">spear-phishing</font>

<font style="color:rgb(21, 28, 43);"></font>

# <font style="color:rgb(31, 31, 31);">Writing Convincing Phishing Emails</font>
<font style="color:rgb(14, 16, 26);">We have three things to work with regarding phishing emails: the sender's email address, the subject and the content.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">关于网络钓鱼电子邮件，我们有三件事要处理：发件人的电子邮件地址、主题和内容。</font>

<font style="color:rgb(14, 16, 26);">  
</font>

**<font style="color:rgb(14, 16, 26);">The Senders Address:</font>****<font style="color:rgb(14, 16, 26);"> </font>****<font style="color:rgb(14, 16, 26);">发件人地址：</font>**

<font style="color:rgb(14, 16, 26);">Ideally, the sender's address would be from a domain name that spoofs a significant brand, a known contact, or a coworker. See the Choosing A</font><font style="color:rgb(14, 16, 26);"> </font><u><font style="color:rgb(14, 16, 26);">Phishing</font></u><font style="color:rgb(14, 16, 26);"> </font><font style="color:rgb(14, 16, 26);">Domain task below for more information on this.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">理想情况下，发件人的地址应来自欺骗重要品牌、已知联系人或同事的域名。有关详细信息，请参阅下面的“选择网络钓鱼域”任务。</font>

<font style="color:rgb(14, 16, 26);">  
</font>

<font style="color:rgb(14, 16, 26);">To find what brands or people a victim interacts with, you can employ</font><font style="color:rgb(14, 16, 26);"> </font><u><font style="color:rgb(14, 16, 26);">OSINT</font></u><font style="color:rgb(14, 16, 26);"> </font><font style="color:rgb(14, 16, 26);">(Open Source Intelligence) tactics. For example:</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">要查找受害者与哪些品牌或人员互动，您可以采用 OSINT（开源情报）策略。例如：</font>

<font style="color:rgb(14, 16, 26);">  
</font>

+ <font style="color:rgb(14, 16, 26);">Observe their social media account for any brands or friends they talk to.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">观察他们的社交媒体帐户，了解与他们交谈的任何品牌或朋友。</font>
+ <font style="color:rgb(14, 16, 26);">Searching Google for the victim's name and rough location for any reviews the victim may have left about local businesses or brands.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">在 Google 上搜索受害者的姓名和大致位置，了解受害者可能留下的有关当地企业或品牌的任何评论。</font>
+ <font style="color:rgb(14, 16, 26);">Looking at the victim's business website to find suppliers.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">查看受害者的商业网站以查找供应商。</font>
+ <font style="color:rgb(14, 16, 26);">Looking at LinkedIn to find coworkers of the victim.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">查看LinkedIn以查找受害者的同事。</font>

**<font style="color:rgb(14, 16, 26);">The Subject:</font>****<font style="color:rgb(14, 16, 26);"> </font>****<font style="color:rgb(14, 16, 26);">主题：</font>**

<font style="color:rgb(14, 16, 26);">You should set the subject to something quite urgent, worrying, or piques the victim's curiosity, so they do not ignore it and act on it quickly.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">你应该把话题放在一些非常紧急、令人担忧的事情上，或者激起受害者的好奇心，这样他们就不会忽视它并迅速采取行动。</font>

<font style="color:rgb(14, 16, 26);">  
</font>

<font style="color:rgb(14, 16, 26);">Examples of this could be:</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">这方面的例子可以是：</font>

1. <font style="color:rgb(14, 16, 26);">Your account has been compromised.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">您的帐户已被盗用。</font>
2. <font style="color:rgb(14, 16, 26);">Your package has been dispatched/shipped.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">您的包裹已发货/发货。</font>
3. <font style="color:rgb(14, 16, 26);">Staff payroll information (do not forward!)</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">员工工资单信息（请勿转发！</font>
4. <font style="color:rgb(14, 16, 26);">Your photos have been published.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">您的照片已发布。</font>

<font style="color:rgb(14, 16, 26);">  
</font>

**<font style="color:rgb(14, 16, 26);">The Content:</font>****<font style="color:rgb(14, 16, 26);"> </font>****<font style="color:rgb(14, 16, 26);">内容：</font>**

<font style="color:rgb(14, 16, 26);">If impersonating a brand or supplier, it would be pertinent to research their standard email templates and branding (style, logo's images, signoffs etc.) and make your content look the same as theirs, so the victim doesn't expect anything. If impersonating a contact or coworker, it could be beneficial to contact them; first, they may have some branding in their template, have a particular email signature or even something small such as how they refer to themselves, for example, someone might have the name Dorothy and their email is dorothy@company.thm. Still, in their signature, it might say "Best Regards, Dot". Learning these somewhat small things can sometimes have quite dramatic psychological effects on the victim and convince them more to open and act on the email.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">如果冒充品牌或供应商，研究他们的标准电子邮件模板和品牌（样式、徽标图像、签名等）并使您的内容看起来与他们的内容相同是相关的，因此受害者不会期望任何事情。如果冒充联系人或同事，与他们联系可能会有所帮助;首先，他们的模板中可能有一些品牌，有一个特定的电子邮件签名，甚至是一些小的东西，比如他们如何称呼自己，例如，某人可能有 Dorothy 这个名字，他们的电子邮件是 dorothy@company.thm。不过，在他们的签名中，它可能会写着“最好的问候，点”。了解这些小事有时会对受害者产生相当戏剧性的心理影响，并说服他们更多地打开电子邮件并采取行动。</font>

<font style="color:rgb(14, 16, 26);">  
</font>

<font style="color:rgb(14, 16, 26);">If you've set up a spoof website to harvest data or distribute malware, the links to this should be disguised using the </font>[anchor text](https://en.wikipedia.org/wiki/Anchor_text)<font style="color:rgb(14, 16, 26);"> and changing it either to some text which says "Click Here" or changing it to a correct looking link that reflects the business you are spoofing, for example:  
</font><font style="color:rgb(14, 16, 26);">如果您设置了一个欺骗网站来收集数据或分发恶意软件，则应使用锚文本伪装指向此链接的链接，并将其更改为显示“单击此处”的文本，或将其更改为反映您正在欺骗的业务的正确外观链接，例如：</font>

**<font style="color:rgb(255, 255, 255);background-color:rgb(33, 44, 66);">  
</font>****<font style="color:rgb(255, 255, 255);background-color:rgb(33, 44, 66);"><a href="http://spoofsite.thm">Click Here</a></font>**

**<font style="color:rgb(255, 255, 255);background-color:rgb(33, 44, 66);"><a href="http://spoofsite.thm">https://onlinebank.thm</a></font>**

**<font style="color:rgb(255, 255, 255);background-color:rgb(33, 44, 66);"></font>**

## <font style="color:rgb(235, 0, 55);">Answer the questions below  
</font><font style="color:rgb(235, 0, 55);">回答以下问题</font>
<font style="color:rgb(235, 0, 55);"></font>

<font style="color:rgb(21, 28, 43);">What tactic can be used to find brands or people a victim interacts with?</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">可以使用什么策略来寻找受害者与之互动的品牌或人？</font>

- [ ] <font style="color:rgb(14, 16, 26);">OSINT（开源情报）策略</font>

<font style="color:rgb(21, 28, 43);"></font>

<font style="color:rgb(21, 28, 43);">What should be changed on an HTML anchor tag to disguise a link?  
</font><font style="color:rgb(21, 28, 43);">HTML 锚标记上应该更改哪些内容以伪装链接？</font>

<font style="color:rgb(14, 16, 26);"> </font>[<font style="color:rgb(14, 16, 26);">anchor text</font>](https://en.wikipedia.org/wiki/Anchor_text)<font style="color:rgb(14, 16, 26);">   锚文本</font><font style="color:rgb(14, 16, 26);">  
</font>

# <font style="color:rgb(31, 31, 31);">Phishing Infrastructure</font>
<font style="color:rgb(14, 16, 26);">A certain amount of infrastructure will need to be put in place to launch a successful phishing campaign.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">需要建立一定数量的基础设施才能成功发起网络钓鱼活动。</font>

<font style="color:rgb(14, 16, 26);">  
</font>

**<font style="color:rgb(14, 16, 26);">Domain Name:</font>****<font style="color:rgb(14, 16, 26);"> </font>****<font style="color:rgb(14, 16, 26);">域名：</font>**

<font style="color:rgb(14, 16, 26);">You'll need to register either an authentic-looking domain name or one that mimics the identity of another domain. See task 5 for details on how to create the perfect domain name.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">您需要注册一个看起来很真实的域名或一个模仿另一个域名身份的域名。有关如何创建完美域名的详细信息，请参阅任务 5。</font>

<font style="color:rgb(14, 16, 26);">  
</font>

**<font style="color:rgb(14, 16, 26);">SSL/TLS Certificates:</font>****<font style="color:rgb(14, 16, 26);"> </font>****<font style="color:rgb(14, 16, 26);">SSL/TLS 证书：</font>**

<font style="color:rgb(14, 16, 26);">Creating SSL/TLS certificates for your chosen domain name will add an extra layer of authenticity to the attack.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">为您选择的域名创建 SSL/TLS 证书将为攻击增加一层额外的真实性。</font>

<font style="color:rgb(14, 16, 26);">  
</font>

**<font style="color:rgb(14, 16, 26);">Email Server/Account:</font>****<font style="color:rgb(14, 16, 26);"> </font>****<font style="color:rgb(14, 16, 26);">电子邮件服务器/帐户：</font>**

<font style="color:rgb(14, 16, 26);">You'll need to either set up an email server or register with an</font><font style="color:rgb(14, 16, 26);"> </font><u><font style="color:rgb(14, 16, 26);">SMTP</font></u><font style="color:rgb(14, 16, 26);"> </font><font style="color:rgb(14, 16, 26);">email provider. </font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">您需要设置电子邮件服务器或向 SMTP 电子邮件提供商注册。</font>

<font style="color:rgb(14, 16, 26);">  
</font>

**<u><font style="color:rgb(14, 16, 26);">DNS</font></u>****<font style="color:rgb(14, 16, 26);"> </font>****<font style="color:rgb(14, 16, 26);">Records:</font>****<font style="color:rgb(14, 16, 26);"> </font>****<font style="color:rgb(14, 16, 26);">DNS 记录：</font>**

<font style="color:rgb(14, 16, 26);">Setting up DNS Records such as SPF, DKIM, DMARC will improve the deliverability of your emails and make sure they're getting into the inbox rather than the spam folder.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">设置 SPF、DKIM、DMARC 等 DNS 记录将提高电子邮件的送达率，并确保它们进入收件箱而不是垃圾邮件文件夹。</font>

<font style="color:rgb(14, 16, 26);">  
</font>

**<font style="color:rgb(14, 16, 26);">Web Server:</font>****<font style="color:rgb(14, 16, 26);"> </font>****<font style="color:rgb(14, 16, 26);">网页服务器：</font>**

<font style="color:rgb(14, 16, 26);">You'll need to set up webservers or purchase web hosting from a company to host your phishing websites. Adding SSL/TLS to the websites will give them an extra layer of authenticity. </font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">您需要设置网络服务器或从公司购买网络托管来托管您的网络钓鱼网站。将SSL / TLS添加到网站将为其提供额外的真实性。</font>

<font style="color:rgb(14, 16, 26);">  
</font>

**<font style="color:rgb(14, 16, 26);">Analytics:</font>****<font style="color:rgb(14, 16, 26);"> </font>****<font style="color:rgb(14, 16, 26);">分析学：</font>**

<font style="color:rgb(14, 16, 26);">When a phishing campaign is part of a red team engagement, keeping analytics information is more important. You'll need something to keep track of the emails that have been sent, opened or clicked. You'll also need to combine it with information from your phishing websites for which users have supplied personal information or downloaded software. </font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">当网络钓鱼活动是红队参与的一部分时，保留分析信息更为重要。您需要一些东西来跟踪已发送、打开或单击的电子邮件。您还需要将其与用户提供个人信息或下载软件的网络钓鱼网站中的信息相结合。</font>

<font style="color:rgb(14, 16, 26);"></font>

**<font style="color:rgb(14, 16, 26);">Automation And Useful Software:</font>****<font style="color:rgb(14, 16, 26);">  
</font>****<font style="color:rgb(14, 16, 26);">自动化和有用的软件：</font>**

<font style="color:rgb(14, 16, 26);">Some of the above infrastructures can be quickly automated by using the below tools.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">使用以下工具可以快速实现上述一些基础设施的自动化。</font>

<font style="color:rgb(14, 16, 26);">  
</font>

**<font style="color:rgb(14, 16, 26);">GoPhish - (Open-Source Phishing Framework) -</font>****<font style="color:rgb(14, 16, 26);"> </font>**[getgophish.com](https://getgophish.com/)**<font style="color:rgb(14, 16, 26);">  
</font>****<font style="color:rgb(14, 16, 26);">GoPhish -（开源网络钓鱼框架）-getgophish.com</font>****<font style="color:rgb(14, 16, 26);">  
</font>**

<font style="color:rgb(14, 16, 26);">GoPhish is a web-based framework to make setting up phishing campaigns more straightforward. GoPhish allows you to store your</font><font style="color:rgb(14, 16, 26);"> </font><u><font style="color:rgb(14, 16, 26);">SMTP</font></u><font style="color:rgb(14, 16, 26);"> </font><font style="color:rgb(14, 16, 26);">server settings for sending emails, has a web-based tool for creating email templates using a simple WYSIWYG (What You See Is What You Get) editor. You can also schedule when emails are sent and have an analytics dashboard that shows how many emails have been sent, opened or clicked.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">GoPhish 是一个基于 Web 的框架，可使设置网络钓鱼活动更加简单。GoPhish允许您存储用于发送电子邮件的SMTP服务器设置，具有基于Web的工具，用于使用简单的WYSIWYG（所见即所得）编辑器创建电子邮件模板。您还可以安排电子邮件的发送时间，并有一个分析仪表板，显示已发送、打开或点击的电子邮件数量。</font>

<font style="color:rgb(14, 16, 26);">  
</font>

<font style="color:rgb(14, 16, 26);">The Next task will talk you through how to launch a phishing campaign using this software.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">下一个任务将向您介绍如何使用此软件发起网络钓鱼活动。</font><font style="color:rgb(14, 16, 26);">  
</font>

<font style="color:rgb(14, 16, 26);">  
</font>

**<font style="color:rgb(14, 16, 26);">SET - (Social Engineering Toolkit) -</font>****<font style="color:rgb(14, 16, 26);"> </font>**[trustedsec.com](https://www.trustedsec.com/tools/the-social-engineer-toolkit-set/)**<font style="color:rgb(14, 16, 26);">  
</font>****<font style="color:rgb(14, 16, 26);">SET - （社会工程工具包） - trustedsec.com</font>****<font style="color:rgb(14, 16, 26);">  
</font>**

<font style="color:rgb(14, 16, 26);">The Social Engineering Toolkit contains a multitude of tools, but some of the important ones for phishing are the ability to create</font><font style="color:rgb(14, 16, 26);"> </font><u><font style="color:rgb(14, 16, 26);">spear-phishing</font></u><font style="color:rgb(14, 16, 26);"> </font><font style="color:rgb(14, 16, 26);">attacks and deploy fake versions of common websites to trick victims into entering their credentials.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">社会工程工具包包含多种工具，但网络钓鱼的一些重要工具是能够创建鱼叉式网络钓鱼攻击并部署常见网站的虚假版本以诱骗受害者输入其凭据。</font>

<font style="color:rgb(14, 16, 26);">  
</font>

<font style="color:rgb(14, 16, 26);">  
</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712329426538-350e9f72-39e0-4c72-b28b-2697dfc5adb7.png)<font style="color:rgb(14, 16, 26);">  
</font>

<font style="color:rgb(14, 16, 26);">  
</font>

<font style="color:rgb(14, 16, 26);">  
</font>

## <font style="color:rgb(235, 0, 55);">Answer the questions below  
</font><font style="color:rgb(235, 0, 55);">回答以下问题</font>
<font style="color:rgb(235, 0, 55);"></font>

<font style="color:rgb(21, 28, 43);">What part of a red team infrastructure can make a website look more authentic?  
</font><font style="color:rgb(21, 28, 43);">红队基础设施的哪一部分可以使网站看起来更真实？</font>

**<font style="color:rgb(14, 16, 26);">SSL/TLS Certificates:</font>****<font style="color:rgb(14, 16, 26);"> </font>****<font style="color:rgb(14, 16, 26);">SSL/TLS 证书：</font>**

**<font style="color:rgb(14, 16, 26);">  
</font>****<font style="color:rgb(14, 16, 26);"> </font>**<font style="color:rgb(21, 28, 43);">What protocol has TXT records that can improve email deliverability?  
</font><font style="color:rgb(21, 28, 43);">TXT记录的哪些协议可以提高电子邮件的送达率？</font>

<font style="color:rgb(21, 28, 43);">DNS</font>

<font style="color:rgb(21, 28, 43);"></font>

<font style="color:rgb(21, 28, 43);">What tool can automate a phishing campaign and include analytics?  
</font><font style="color:rgb(21, 28, 43);">什么工具可以自动执行网络钓鱼活动并包含分析？</font>

<font style="color:rgb(14, 16, 26);">GoPhish</font>

# <font style="color:rgb(31, 31, 31);">Using GoPhish</font>
<font style="color:rgb(21, 28, 43);">This task will take you through setting up GoPhish, sending a phishing campaign and capturing user credentials from a spoof website.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">此任务将引导您完成设置GoPhish，发送网络钓鱼活动以及从欺骗网站捕获用户凭据。</font><font style="color:rgb(21, 28, 43);">  
</font>

<font style="color:rgb(21, 28, 43);">Firstly launch the virtual machine by clicking the green</font><font style="color:rgb(21, 28, 43);"> </font>**<font style="color:rgb(21, 28, 43);">Start Machine</font>**<font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">button on the right; once loaded, click the following URL to open the GoPhish login page</font><font style="color:rgb(21, 28, 43);"> </font>[https://LAB_WEB_URL.p.thmlabs.com:8443](https://lab_web_url.p.thmlabs.com:8443/)<font style="color:rgb(21, 28, 43);">  or if you're connected to the TryHackMe VPN, you can to go</font><font style="color:rgb(21, 28, 43);"> </font>[https://MACHINE_IP](https://machine_ip/)<font style="color:rgb(21, 28, 43);">  (if you receive an Nginx error, wait another 30 seconds and try again).</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">首先，通过单击右侧绿色的“启动计算机”按钮启动虚拟机;加载后，单击以下 URL 打开 GoPhish 登录页面 https：//LAB_WEB_URL.p.thmlabs.com：8443，或者如果您已连接到 TryHackMe VPN，您可以转到 https：//MACHINE_IP（如果您收到 Nginx 错误，请再等待 30 秒，然后重试）。</font><font style="color:rgb(21, 28, 43);">  
</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712333988638-42a7f0dd-82b8-4a16-af84-98337aa7265c.png)<font style="color:rgb(21, 28, 43);">  
</font>

<font style="color:rgb(21, 28, 43);">You should be able to log in with the username:</font><font style="color:rgb(21, 28, 43);"> </font>**<font style="color:rgb(21, 28, 43);">admin</font>**<font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">and password:</font><font style="color:rgb(21, 28, 43);"> </font>**<font style="color:rgb(21, 28, 43);">tryhackme</font>**<font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">您应该能够使用用户名：admin和密码：tryhackme 登录</font>

**<font style="color:rgb(21, 28, 43);">Sending Profiles:</font>****<font style="color:rgb(21, 28, 43);"> </font>****<font style="color:rgb(21, 28, 43);">发送配置文件：</font>**<font style="color:rgb(21, 28, 43);">  
</font>

<font style="color:rgb(21, 28, 43);">Sending profiles are the connection details required to actually send your Phishing emails; this is just simply an SMTP server that you have access to. Click the Sending Profiles link on the left-hand menu and then click the "New Profile" button.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">发送配置文件是实际发送网络钓鱼电子邮件所需的连接详细信息;这只是您有权访问的 SMTP 服务器。单击左侧菜单上的“发送配置文件”链接，然后单击“新建配置文件”按钮。</font>

<font style="color:rgb(21, 28, 43);">Next, add in the following information as per the screenshot below:</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">接下来，根据下面的屏幕截图添加以下信息：</font>

<font style="color:rgb(21, 28, 43);">Name:</font><font style="color:rgb(21, 28, 43);"> </font>**<font style="color:rgb(21, 28, 43);">Local Server</font>**<font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">名称：本地服务器</font>

<font style="color:rgb(21, 28, 43);">From:</font><font style="color:rgb(21, 28, 43);"> </font>**<font style="color:rgb(21, 28, 43);">noreply@redteam.thm</font>**<font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">来自： noreply@redteam.thm</font>

<font style="color:rgb(21, 28, 43);">Host:</font><font style="color:rgb(21, 28, 43);"> </font>**<font style="color:rgb(21, 28, 43);">127.0.0.1:25</font>**<font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">主机：127.0.0.1：25</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712333988594-90306f3d-0538-41f1-8a9d-1fd82923542b.png)<font style="color:rgb(21, 28, 43);">  
</font>

<font style="color:rgb(21, 28, 43);">Then click</font><font style="color:rgb(21, 28, 43);"> </font>**<font style="color:rgb(21, 28, 43);">Save Profile</font>**<font style="color:rgb(21, 28, 43);">.</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">然后单击保存配置文件。</font><font style="color:rgb(21, 28, 43);">  
</font>

**<font style="color:rgb(21, 28, 43);">Landing Pages:</font>****<font style="color:rgb(21, 28, 43);"> </font>****<font style="color:rgb(21, 28, 43);">登陆页面：</font>**

<font style="color:rgb(21, 28, 43);">Next, we're going to set up the landing page; this is the website that the</font><font style="color:rgb(21, 28, 43);"> </font><u><font style="color:rgb(21, 28, 43);">Phishing</font></u><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">email is going to direct the victim to; this page is usually a spoof of a website the victim is familiar with.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">接下来，我们将设置登录页面;这是网络钓鱼电子邮件将引导受害者访问的网站;此页面通常是对受害者熟悉的网站的恶搞。</font><font style="color:rgb(21, 28, 43);">  
</font>

<font style="color:rgb(21, 28, 43);">Click the Landing Pages link on the left-hand menu and then click the "New Page" button.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">单击左侧菜单上的“登录页面”链接，然后单击“新建页面”按钮。</font>

<font style="color:rgb(21, 28, 43);">Give the Landing Page the name</font><font style="color:rgb(21, 28, 43);"> </font>**<font style="color:rgb(21, 28, 43);">ACME Login</font>**<font style="color:rgb(21, 28, 43);">, next in the HTML box; you'll need to press the</font><font style="color:rgb(21, 28, 43);"> </font>**<font style="color:rgb(21, 28, 43);">Source</font>**<font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">button to allow us to enter the HTML code as shown below:</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">将登陆页面命名为 ACME 登录名，在 HTML 框中紧随其后;您需要按“源”按钮以允许我们输入 HTML 代码，如下所示：</font>

```plain
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ACME IT SUPPORT - Admin Panel</title>
    <style>
        body { font-family: "Ubuntu", monospace; text-align: center }
        div.login-form { margin:auto; width:300px; border:1px solid #ececec; padding:10px;text-align: left;font-size:13px;}
        div.login-form div input { margin-bottom:7px;}
        div.login-form input { width:280px;}
        div.login-form div:last-child { text-align: center; }
        div.login-form div:last-child input { width:100px;}
    </style>
</head>
<body>
    <h2>ACME IT SUPPORT</h2>
    <h3>Admin Panel</h3>
    <form method="post">
        <div class="login-form">
            <div>Username:</div>
            <div><input name="username"></div>
            <div>Password:</div>
            <div><input type="password" name="password"></div>
            <div><input type="submit" value="Login"></div>
        </div>
    </form>
</body>
</html>
```

<font style="color:rgb(21, 28, 43);">Click the</font><font style="color:rgb(21, 28, 43);"> </font>**<font style="color:rgb(21, 28, 43);">Source</font>**<font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">button again, and you should see a login box with username and password fields as per the image below, also click the</font><font style="color:rgb(21, 28, 43);"> </font>**<font style="color:rgb(21, 28, 43);">Capture Submitted Data</font>**<font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">box and then also the</font><font style="color:rgb(21, 28, 43);"> </font>**<font style="color:rgb(21, 28, 43);">Capture Passwords</font>**<font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">box and then click the Save Page button.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">再次单击“源”按钮，您应该会看到一个带有用户名和密码字段的登录框，如下图所示，同时单击“捕获提交的数据”框，然后单击“捕获密码”框，然后单击“保存页面”按钮。</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712333988856-11fbf77f-02e0-4d6c-9f2c-c65c325995ff.png)<font style="color:rgb(21, 28, 43);">  
</font>

**<font style="color:rgb(21, 28, 43);">Email Templates:</font>****<font style="color:rgb(21, 28, 43);"> </font>****<font style="color:rgb(21, 28, 43);">电子邮件模板：</font>**

<font style="color:rgb(21, 28, 43);">This is the design and content of the email you're going to actually send to the victim; it will need to be persuasive and contain a link to your landing page to enable us to capture the victim's username and password. Click the</font><font style="color:rgb(21, 28, 43);"> </font>**<font style="color:rgb(21, 28, 43);">Email Templates</font>**<font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">link on the left-hand menu and then click the</font><font style="color:rgb(21, 28, 43);"> </font>**<font style="color:rgb(21, 28, 43);">New Template</font>**<font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">button. Give the template the name</font><font style="color:rgb(21, 28, 43);"> </font>**<font style="color:rgb(21, 28, 43);">Email 1</font>**<font style="color:rgb(21, 28, 43);">, the subject</font><font style="color:rgb(21, 28, 43);"> </font>**<font style="color:rgb(21, 28, 43);">New Message Received</font>**<font style="color:rgb(21, 28, 43);">, click the HTML tab, and then the Source button to enable HTML editor mode. In the contents write a persuasive email that would convince the user to click the link, the link text will need to be set to</font><font style="color:rgb(21, 28, 43);"> </font>[https://admin.acmeitsupport.thm](https://admin.acmeitsupport.thm/)<font style="color:rgb(21, 28, 43);">, but the actual link will need to be set to</font><font style="color:rgb(21, 28, 43);"> </font>**<font style="color:rgb(21, 28, 43);">{{.URL}}</font>**<font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">which will get changed to our spoofed landing page when the email gets sent, you can do this by highlighting the link text and then clicking the link button on the top row of icons, make sure to set the</font><font style="color:rgb(21, 28, 43);"> </font>**<font style="color:rgb(21, 28, 43);">protocol</font>**<font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">dropdown to</font><font style="color:rgb(21, 28, 43);"> </font>**<font style="color:rgb(21, 28, 43);"><other></font>**<font style="color:rgb(21, 28, 43);">.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">这是您实际要发送给受害者的电子邮件的设计和内容;它需要具有说服力，并包含指向您的登录页面的链接，以便我们能够捕获受害者的用户名和密码。单击左侧菜单中的“电子邮件模板”链接，然后单击“新建模板”按钮。为模板指定名称“电子邮件 1”，主题为“收到新邮件”，单击“HTML”选项卡，然后单击“源”按钮以启用 HTML 编辑器模式。在内容中，写一封有说服力的电子邮件，说服用户点击链接，链接文本需要设置为 https://admin.acmeitsupport.thm，但实际链接需要设置为{{。URL}}，当电子邮件发送时，它将更改为我们的欺骗性登录页面，您可以通过突出显示链接文本，然后单击顶部图标上的链接按钮来执行此操作，确保将协议下拉列表设置为 <other>.</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712333988797-5d4dc738-aace-4dc4-98c5-3e5274a0b640.png)

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712333988752-defcfbee-7226-48b4-8f84-fc9fff7f11d9.png)

<font style="color:rgb(21, 28, 43);">  
</font>

<font style="color:rgb(21, 28, 43);">  
</font>

<font style="color:rgb(21, 28, 43);">Your email should look similar to the screenshot below. Click</font><font style="color:rgb(21, 28, 43);"> </font>**<font style="color:rgb(21, 28, 43);">Save Template</font>**<font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">once complete.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">您的电子邮件应类似于下面的屏幕截图。完成后单击保存模板。</font><font style="color:rgb(21, 28, 43);">  
</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712333990091-69174506-33ae-44b1-a4d5-a7b49b8c1670.png)

<font style="color:rgb(21, 28, 43);">  
</font>

<font style="color:rgb(21, 28, 43);">  
</font>

<font style="color:rgb(21, 28, 43);">  
</font>

**<font style="color:rgb(21, 28, 43);">Users & Groups</font>****<font style="color:rgb(21, 28, 43);"> </font>****<font style="color:rgb(21, 28, 43);">用户和组</font>**

<font style="color:rgb(21, 28, 43);">This is where we can store the email addresses of our intended targets. Click the</font><font style="color:rgb(21, 28, 43);"> </font>**<font style="color:rgb(21, 28, 43);">Users & Groups</font>**<font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">link on the left-hand menu and then click the</font><font style="color:rgb(21, 28, 43);"> </font>**<font style="color:rgb(21, 28, 43);">New Group</font>**<font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">button. Give the group the name</font><font style="color:rgb(21, 28, 43);"> </font>**<font style="color:rgb(21, 28, 43);">Targets</font>**<font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">and then add the following email addresses:</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">在这里，我们可以存储预期目标的电子邮件地址。单击左侧菜单上的“用户和组”链接，然后单击“新建组”按钮。为组指定名称“目标”，然后添加以下电子邮件地址：</font>

<font style="color:rgb(21, 28, 43);">martin@acmeitsupport.thm  
</font><font style="color:rgb(21, 28, 43);">brian@acmeitsupport.thm  
</font><font style="color:rgb(21, 28, 43);">accounts@acmeitsupport.thm  
  
</font>

<font style="color:rgb(21, 28, 43);">Click the</font><font style="color:rgb(21, 28, 43);"> </font>**<font style="color:rgb(21, 28, 43);">Save Template</font>**<font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">button; once completed, it should look like the below screenshot:</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">单击“保存模板”按钮;完成后，它应该看起来像下面的屏幕截图：</font><font style="color:rgb(21, 28, 43);">  
</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712333990108-2f2a14d6-356b-41ef-8bba-0e3affba7174.png)<font style="color:rgb(21, 28, 43);">  
</font>

**<font style="color:rgb(21, 28, 43);">Campaigns</font>****<font style="color:rgb(21, 28, 43);"> </font>****<font style="color:rgb(21, 28, 43);">活动</font>**

<font style="color:rgb(21, 28, 43);">Now it's time to send your first emails; click the</font><font style="color:rgb(21, 28, 43);"> </font>**<font style="color:rgb(21, 28, 43);">Campaigns</font>**<font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">link on the left-hand menu and then click the</font><font style="color:rgb(21, 28, 43);"> </font>**<font style="color:rgb(21, 28, 43);">New Campaign</font>**<font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">button. Set the following values for the inputs, as per the screenshot below:</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">现在是时候发送您的第一封电子邮件了;单击左侧菜单中的“广告系列”链接，然后单击“新建广告系列”按钮。为输入设置以下值，如下面的屏幕截图所示：</font>

<font style="color:rgb(21, 28, 43);">Name: Campaign One</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">名称：战役一</font>

<font style="color:rgb(21, 28, 43);">Email Template: Email 1</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">电子邮件模板：电子邮件 1</font>

<font style="color:rgb(21, 28, 43);">Landing Page: ACME Login</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">登陆页面：ACME登录</font>

<font style="color:rgb(21, 28, 43);">URL:</font><font style="color:rgb(21, 28, 43);"> </font>[http://MACHINE_IP](http://machine_ip/)<font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">公司主页： http：//MACHINE_IP</font>

<font style="color:rgb(21, 28, 43);">Launch Date: For this lab set it to 2 days ago just to make sure there is no complication with different timezones, in a real operation this would be set correctly.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">启动日期：对于此实验室，将其设置为 2 天前，以确保不同时区不会出现复杂情况，在实际操作中，这将正确设置。</font><font style="color:rgb(21, 28, 43);">  
</font>

<font style="color:rgb(21, 28, 43);">Sending Profile: Local Server</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">发送配置文件：本地服务器</font>

<font style="color:rgb(21, 28, 43);">Groups: Targets</font><font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">组：目标</font>

<font style="color:rgb(21, 28, 43);">Once completed, click the</font><font style="color:rgb(21, 28, 43);"> </font>**<font style="color:rgb(21, 28, 43);">Launch Campaign</font>**<font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">button, which will produce an</font><font style="color:rgb(21, 28, 43);"> </font>**<font style="color:rgb(21, 28, 43);">Are You Sure</font>**<font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">prompt where you can just press the</font><font style="color:rgb(21, 28, 43);"> </font>**<font style="color:rgb(21, 28, 43);">Launch</font>**<font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">button.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">完成后，单击“启动活动”按钮，这将产生“您确定吗”提示，您只需按“启动”按钮即可。</font><font style="color:rgb(21, 28, 43);">  
</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712333990055-2d598cc2-19ef-439b-9bdb-862e2639e6d5.png)<font style="color:rgb(21, 28, 43);">  
</font>

<font style="color:rgb(21, 28, 43);">You'll then be redirected to the results page of the campaign.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">然后，您将被重定向到广告系列的结果页面。</font>

**<font style="color:rgb(21, 28, 43);">Results</font>****<font style="color:rgb(21, 28, 43);"> </font>****<font style="color:rgb(21, 28, 43);">结果</font>**

<font style="color:rgb(21, 28, 43);">The results page gives us an idea of how the phishing campaign is performing by letting us know how many emails have been delivered, opened, clicked and how many users have submitted data to our spoof website.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">结果页面让我们知道有多少电子邮件被发送、打开、点击，以及有多少用户向我们的欺骗网站提交了数据，让我们了解网络钓鱼活动的执行情况。</font><font style="color:rgb(21, 28, 43);">  
</font>

<font style="color:rgb(21, 28, 43);">You'll see at the bottom of the screen a breakdown for each email address; you'll notice that both Martin's and Brian's email has been sent successfully, but the account's email has resulted in an error.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">您会在屏幕底部看到每个电子邮件地址的明细;您会注意到 Martin 和 Brian 的电子邮件都已成功发送，但该帐户的电子邮件导致错误。</font><font style="color:rgb(21, 28, 43);">  
</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712333990319-0486184c-a250-4060-b587-f0612ec154dc.png)

<font style="color:rgb(21, 28, 43);">We can dig in the error more by clicking the dropdown arrow next to the account's row, and by viewing the details or the error, we can see an error message saying the user is unknown.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">我们可以通过单击帐户行旁边的下拉箭头来进一步挖掘错误，通过查看详细信息或错误，我们可以看到一条错误消息，指出用户未知。</font><font style="color:rgb(21, 28, 43);">  
</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712333990511-0656c468-ba08-4ca0-86a1-b843197b6b1f.png)

<font style="color:rgb(21, 28, 43);">After a minute and providing you've followed the instructions correctly, you should see the status of brian change to</font>**<font style="color:rgb(21, 28, 43);"> </font>****<font style="color:rgb(21, 28, 43);">Submitted Data.</font>**<font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">一分钟后，只要你已正确按照说明操作，您应该会看到 brian 的状态更改为“提交的数据”。</font><font style="color:rgb(21, 28, 43);">  
</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712333991359-a5ac1b06-38e6-48b3-899b-72378afe47f6.png)

<font style="color:rgb(21, 28, 43);">Expanding Brian's details and then viewing the details for the submitted data, you should be able to see Brian's username and password, which will help you answer the question below.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">展开 Brian 的详细信息，然后查看提交数据的详细信息，您应该能够看到 Brian 的用户名和密码，这将帮助您回答以下问题。</font><font style="color:rgb(21, 28, 43);">  
</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712333991455-34bccc42-3bb7-4d95-b4cf-066251386a28.png)<font style="color:rgb(21, 28, 43);">  
</font>

## <font style="color:rgb(235, 0, 55);">Answer the questions below  
</font><font style="color:rgb(235, 0, 55);">回答以下问题</font>
<font style="color:rgb(235, 0, 55);"></font>

<font style="color:rgb(235, 0, 55);"></font>

<font style="color:rgb(21, 28, 43);">What is the password for Brian?  
</font><font style="color:rgb(21, 28, 43);">布莱恩的密码是什么？</font>

<font style="color:rgb(21, 28, 43);">根据上述操作进行即可获得密码</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712337081522-9da138ea-fe21-45d6-9bd3-a1b48b6659d4.png)

# Droppers
<font style="color:rgb(21, 28, 43);">Droppers are software that phishing victims tend to be tricked into downloading and running on their system. The dropper may advertise itself as something useful or legitimate such as a codec to view a certain video or software to open a specific file.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">滴管是网络钓鱼受害者往往被诱骗在其系统上下载和运行的软件。滴管可能会将自己宣传为有用或合法的东西，例如用于查看特定视频的编解码器或用于打开特定文件的软件。</font>

<font style="color:rgb(21, 28, 43);">The droppers are not usually malicious themselves, so they tend to pass antivirus checks. Once installed, the intended malware is either unpacked or downloaded from a server and installed onto the victim's computer. The malicious software usually connects back to the attacker's infrastructure. The attacker can take control of the victim's computer, which can further explore and exploit the local network.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">滴管本身通常不是恶意的，因此它们往往会通过防病毒检查。安装后，预期的恶意软件将被解压缩或从服务器下载并安装到受害者的计算机上。恶意软件通常会连接回攻击者的基础结构。攻击者可以控制受害者的计算机，从而进一步探索和利用本地网络。</font>

<font style="color:rgb(21, 28, 43);"></font>

## <font style="color:rgb(235, 0, 55);">Answer the questions below  
</font><font style="color:rgb(235, 0, 55);">回答以下问题</font>
<font style="color:rgb(235, 0, 55);"></font>

<font style="color:rgb(21, 28, 43);">Do droppers tend to be malicious?  
</font><font style="color:rgb(21, 28, 43);">滴管往往是恶意的吗？</font>

<font style="color:rgb(21, 28, 43);">nay </font>

<font style="color:rgb(21, 28, 43);"></font>

# <font style="color:rgb(31, 31, 31);">Choosing A Phishing Domain</font>
<font style="color:rgb(14, 16, 26);">Choosing the right</font><font style="color:rgb(14, 16, 26);"> </font><u><font style="color:rgb(14, 16, 26);">Phishing</font></u><font style="color:rgb(14, 16, 26);"> </font><font style="color:rgb(14, 16, 26);">domain to launch your attack from is essential to ensure you have the psychological edge over your target. A red team engagement can use some of the below methods for choosing the perfect domain name.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">选择正确的网络钓鱼域来发起攻击对于确保您在目标上具有心理优势至关重要。红队参与可以使用以下一些方法来选择完美的域名。</font>

<font style="color:rgb(14, 16, 26);">  
</font>

**<font style="color:rgb(14, 16, 26);">Expired Domains:</font>****<font style="color:rgb(14, 16, 26);"> </font>****<font style="color:rgb(14, 16, 26);">过期域名：</font>**

<font style="color:rgb(14, 16, 26);">Although not essential, buying a domain name with some history may lead to better scoring of your domain when it comes to spam filters. Spam filters have a tendency to not trust brand new domain names compared to ones with some history.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">虽然不是必需的，但购买具有一定历史记录的域名可能会在垃圾邮件过滤器方面为您的域名带来更好的评分。与具有一定历史记录的域名相比，垃圾邮件过滤器倾向于不信任全新的域名。</font><font style="color:rgb(14, 16, 26);">  
</font>

<font style="color:rgb(14, 16, 26);">  
</font>

**<font style="color:rgb(14, 16, 26);">Typosquatting:</font>****<font style="color:rgb(14, 16, 26);"> </font>****<font style="color:rgb(14, 16, 26);">错别字抢注：</font>**

<font style="color:rgb(14, 16, 26);">Typosquatting is when a registered domain looks very similar to the target domain you're trying to impersonate. Here are some of the common methods:</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">拼写错误是指注册的域看起来与您尝试模拟的目标域非常相似。以下是一些常用方法：</font>

<font style="color:rgb(14, 16, 26);">  
</font>

**<font style="color:rgb(14, 16, 26);">Misspelling:</font>**<font style="color:rgb(14, 16, 26);"> </font><font style="color:rgb(14, 16, 26);">goggle.com Vs google.com</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">拼写错误：goggle.com 与 google.com</font>

**<font style="color:rgb(14, 16, 26);">Additional Period:</font>**<font style="color:rgb(14, 16, 26);"> </font><font style="color:rgb(14, 16, 26);">go.ogle.com Vs google.com</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">附加时段：go.ogle.com VS google.com</font>

**<font style="color:rgb(14, 16, 26);">Switching numbers for letters:</font>**<font style="color:rgb(14, 16, 26);"> </font><font style="color:rgb(14, 16, 26);">g00gle.com Vs</font><font style="color:rgb(14, 16, 26);"> </font><font style="color:rgb(14, 16, 26);">google.com</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">切换字母的数字：g00gle.com 与 google.com</font>

**<font style="color:rgb(14, 16, 26);">Phrasing:</font>**<font style="color:rgb(14, 16, 26);"> </font><font style="color:rgb(14, 16, 26);">googles.com Vs</font><font style="color:rgb(14, 16, 26);"> </font><font style="color:rgb(14, 16, 26);">google.com</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">措辞：googles.com 与 google.com</font>

**<font style="color:rgb(14, 16, 26);">Additional Word:</font>**<font style="color:rgb(14, 16, 26);"> </font><font style="color:rgb(14, 16, 26);">googleresults.com Vs</font><font style="color:rgb(14, 16, 26);"> </font><font style="color:rgb(14, 16, 26);">google.com</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">附加词：googleresults.com 与 google.com</font>

<font style="color:rgb(14, 16, 26);">  
</font>

<font style="color:rgb(14, 16, 26);">These changes might look unrealistic, but at a glance, the human brain tends to fill in the blanks and see what it wants to see, i.e. the correct domain name.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">这些变化可能看起来不切实际，但乍一看，人脑倾向于填补空白，看看它想看到什么，即正确的域名。</font>

<font style="color:rgb(14, 16, 26);">  
</font>

**<font style="color:rgb(14, 16, 26);">TLD Alternatives:</font>****<font style="color:rgb(14, 16, 26);"> </font>****<font style="color:rgb(14, 16, 26);">TLD替代方案：</font>**

<font style="color:rgb(14, 16, 26);">A TLD (Top Level Domain) is the .com .net .co.uk .org .gov e.t.c part of a domain name, there are 100's of variants of TLD's now. A common trick for choosing a domain would be to use the same name but with a different TLD. For example, register tryhackme.co.uk to impersonate tryhackme.com.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">TLD（顶级域名）是域名.com.net .co.uk.org .gov等域名的一部分，现在有100多种顶级域名的变体。选择域名的一个常见技巧是使用相同的名称，但使用不同的顶级域名。例如，注册 tryhackme.co.uk 以模拟 tryhackme.com。</font>

<font style="color:rgb(14, 16, 26);">  
</font>

**<font style="color:rgb(14, 16, 26);">IDN Homograph Attack/Script Spoofing:</font>****<font style="color:rgb(14, 16, 26);">  
</font>****<font style="color:rgb(14, 16, 26);">IDN 同形异义词攻击/脚本欺骗：</font>**

<font style="color:rgb(14, 16, 26);">Originally domain names were made up of Latin characters a-z and 0-9, but in 1998, IDN (internationalized domain name) was implemented to support language-specific script or alphabet from other languages such as Arabic, Chinese, Cyrillic, Hebrew and more. An issue that arises from the IDN implementation is that different letters from different languages can actually appear identical. For example, Unicode character U+0430 (Cyrillic small letter a) looks identical to Unicode character U+0061 (Latin small letter a) used in English, enabling attackers to register a domain name that looks almost identical to another.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">最初域名由拉丁字符 a-z 和 0-9 组成，但在 1998 年，实施了 IDN（国际化域名）以支持来自其他语言（如阿拉伯语、中文、西里尔语、希伯来语等）的特定语言脚本或字母。IDN 实现中出现的一个问题是，来自不同语言的不同字母实际上可能看起来相同。例如，Unicode 字符 U+0430（西里尔文小写字母 a）看起来与英语中使用的 Unicode 字符 U+0061（拉丁文小写字母 a）相同，使攻击者能够注册一个看起来几乎相同的域名。</font>

![](https://cdn.nlark.com/yuque/0/2024/png/40628873/1712367483325-bb4489ae-8dd5-462c-a48d-955a244bff06.png)

## <font style="color:rgb(235, 0, 55);">Answer the questions below  
</font><font style="color:rgb(235, 0, 55);">回答以下问题</font>
<font style="color:rgb(21, 28, 43);">What is better, using an expired or new domain? (old/new)  
</font><font style="color:rgb(21, 28, 43);">使用过期域名还是新域名哪个更好？（旧/新）</font>

<font style="color:rgb(21, 28, 43);">old</font>

<font style="color:rgb(21, 28, 43);">What is the term used to describe registering a similar domain name with a spelling error?  
</font><font style="color:rgb(21, 28, 43);">用于描述注册拼写错误的类似域名的术语是什么？</font>

<font style="color:rgb(14, 16, 26);">Typosquatting   错别字抢注</font>

# <font style="color:rgb(31, 31, 31);">Using MS Office In Phishing</font>
<font style="color:rgb(14, 16, 26);">Often during phishing campaigns, a Microsoft Office document (typically Word, Excel or PowerPoint) will be included as an attachment. Office documents can contain macros; macros do have a legitimate use but can also be used to run computer commands that can cause malware to be installed onto the victim's computer or connect back to an attacker's network and allow the attacker to take control of the victim's computer.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">通常在网络钓鱼活动期间，Microsoft Office 文档（通常是 Word、Excel 或 PowerPoint）将作为附件包含在内。Office 文档可以包含宏;宏确实具有合法用途，但也可用于运行计算机命令，这些命令可能导致恶意软件安装到受害者的计算机上或连接回攻击者的网络并允许攻击者控制受害者的计算机。</font>

<font style="color:rgb(14, 16, 26);">  
</font>

**<font style="color:rgb(14, 16, 26);">Take, for example, the following scenario:</font>****<font style="color:rgb(14, 16, 26);">  
</font>****<font style="color:rgb(14, 16, 26);">以以下方案为例：</font>**

<font style="color:rgb(14, 16, 26);">  
</font>

<font style="color:rgb(14, 16, 26);">A staff member working for Acme IT Support receives an email from human resources with an excel spreadsheet called "Staff_Salaries.xlsx" intended to go to the boss but somehow ended up in the staff members inbox instead. </font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">Acme IT 支持部门的一名员工收到一封来自人力资源部的电子邮件，其中包含一个名为“Staff_Salaries.xlsx”的 excel 电子表格，打算发送给老板，但不知何故最终进入了员工收件箱。</font>

<font style="color:rgb(14, 16, 26);">  
</font>

<font style="color:rgb(14, 16, 26);">What really happened was that an attacker spoofed the human resources email address and crafted a psychologically tempting email perfectly aimed to tempt the staff member into opening the attachment.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">真正发生的事情是，攻击者欺骗了人力资源电子邮件地址，并制作了一封心理上诱人的电子邮件，旨在诱使工作人员打开附件。</font>

<font style="color:rgb(14, 16, 26);">  
</font>

<font style="color:rgb(14, 16, 26);">Once the staff member opened the attachment and enabled the macros, their computer was compromised.</font><font style="color:rgb(14, 16, 26);">  
</font><font style="color:rgb(14, 16, 26);">一旦工作人员打开附件并启用宏，他们的计算机就会受到威胁。</font>

## <font style="color:rgb(235, 0, 55);">Answer the questions below  
</font><font style="color:rgb(235, 0, 55);">回答以下问题</font>
<font style="color:rgb(235, 0, 55);"></font>

<font style="color:rgb(21, 28, 43);">What can Microsoft Office documents contain, which, when executed can run computer commands?  
</font><font style="color:rgb(21, 28, 43);">Microsoft Office 文档可以包含哪些内容，执行时可以运行计算机命令？</font>

<font style="color:rgb(21, 28, 43);">macros</font>

<font style="color:rgb(21, 28, 43);"></font>

# <font style="color:rgb(31, 31, 31);">Using Browser Exploits</font>
<font style="color:rgb(21, 28, 43);">Another method of gaining control over a victim's computer could be through browser exploits; this is when there is a vulnerability against a browser itself (Internet Explorer/Edge, Firefox, Chrome, Safari, etc.), which allows the attacker to run remote commands on the victim's computer.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">另一种控制受害者计算机的方法可能是通过浏览器漏洞利用;这是当存在针对浏览器本身（Internet Explorer/Edge、Firefox、Chrome、Safari 等）的漏洞时，攻击者可以在受害者的计算机上运行远程命令。</font><font style="color:rgb(21, 28, 43);">  
  
</font><font style="color:rgb(21, 28, 43);">Browser exploits aren't usually a common path to follow in a red team engagement unless you have prior knowledge of old technology being used on-site. Many browsers are kept up to date, hard to exploit due to how browsers are developed, and the exploits are often worth a lot of money if reported back to the developers.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">浏览器漏洞通常不是红队参与的常见路径，除非您事先了解现场使用的旧技术。许多浏览器都是最新的，由于浏览器的开发方式而难以利用，如果向开发人员报告，这些漏洞通常价值不菲。</font><font style="color:rgb(21, 28, 43);">  
  
</font><font style="color:rgb(21, 28, 43);">That being said, it can happen, and as previously mentioned, it could be used to target old technologies on-site because possibly the browser software cannot be updated due to incompatibility with commercial software/hardware, which can happen quite often in big institutions such as education, government and especially health care.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">话虽如此，它可能会发生，如前所述，它可用于针对现场的旧技术，因为浏览器软件可能由于与商业软件/硬件不兼容而无法更新，这在教育、政府等大型机构中经常发生，尤其是医疗保健。</font><font style="color:rgb(21, 28, 43);">  
  
</font><font style="color:rgb(21, 28, 43);">Usually, the victim would receive an email, convincing them to visit a particular website set up by the attacker. Once the victim is on the site, the exploit works against the browser, and now the attacker can perform any commands they wish on the victim's computer.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">通常，受害者会收到一封电子邮件，说服他们访问攻击者设置的特定网站。一旦受害者进入该站点，该漏洞就会对浏览器起作用，现在攻击者可以在受害者的计算机上执行他们想要的任何命令。</font>

<font style="color:rgb(21, 28, 43);">An example of this is</font><font style="color:rgb(21, 28, 43);"> </font>[CVE-2021-40444](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444)<font style="color:rgb(21, 28, 43);"> </font><font style="color:rgb(21, 28, 43);">from September 2021, which is a vulnerability found in Microsoft systems that allowed the execution of code just from visiting a website.</font><font style="color:rgb(21, 28, 43);">  
</font><font style="color:rgb(21, 28, 43);">这方面的一个例子是 2021 年 9 月的 CVE-2021-40444，这是在 Microsoft 系统中发现的漏洞，允许仅通过访问网站执行代码。</font><font style="color:rgb(21, 28, 43);">  
</font>

## <font style="color:rgb(235, 0, 55);">Answer the questions below  
</font><font style="color:rgb(235, 0, 55);">回答以下问题</font>
<font style="color:rgb(21, 28, 43);">Which recent CVE caused remote code execution?  
</font><font style="color:rgb(21, 28, 43);">最近的哪个 CVE 导致了远程代码执行？</font>

[<font style="color:rgb(21, 28, 43);">CVE-2021-40444</font>](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444)<font style="color:rgb(21, 28, 43);"> </font>




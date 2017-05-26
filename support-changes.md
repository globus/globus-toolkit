## Support for open source Globus Toolkit will end as of January 2018; The Globus cloud service and Globus Connect are unaffected
 	
The Globus team at the University of Chicago has developed and supported the open source [Globus Toolkit](https://www.globustoolkit.org) for close to 20 years. 
Globus Toolkit GridFTP and GSI software, in particular, 
have been widely used within the scientific community for data transfer and security. 
Since 2010, we have leveraged that experience to develop the [Globus cloud service](https://www.globus.org), which provides enhanced capabilities for data transfer plus new identity and group management, data sharing, data publication, and other functions. Most Globus Toolkit users have by now moved to the Globus cloud service and the associated Globus Connect endpoint software, used by tens of thousands of people to manage billions of files on more than 10,000 active endpoints. Importantly, a subscription-based sustainability model allows the Globus team to assure Globus cloud service users of our long-term viability.
 
We are announcing that, starting in January 2018, the Globus team at the University of Chicago will no longer support the open source Globus Toolkit, except for its use with the Globus cloud service by Globus subscribers. By the end of 2018, all endpoints connected to the Globus cloud service using the open source Globus Toolkit GridFTP server must migrate to Globus Connect. At the end of 2018, we will discontinue all maintenance (including security patches) and distribution of the open source Globus Toolkit. Endpoints using Globus Connect Server or Globus Connect Personal will be unaffected, as long as they continue to perform routine software updates.
 
We realize that this change in long-established practice may create challenges for those users who have not migrated to the Globus cloud service, and so we explain here first the reason for this change, and second, why we recommend that remaining Globus Toolkit users migrate to the Globus cloud service. Note that this change in support policy only affects direct users of the open source Globus Toolkit. Users of the Globus cloud service, and sites running Globus Connect to make their storage systems accessible via the Globus cloud service, are unaffected. 
 
**Why we are ceasing support of the open source Globus Toolkit**. 
In a word, funding. The open source Globus Toolkit, like any software, requires constant effort to answer support requests, apply security patches, and perform other maintenance. This work has long been financed by grants, primarily from the U.S. National Science Foundation (NSF). However, our last such grant ends this fall and, after extensive discussions with funding agencies and Globus Toolkit users, we see little opportunity for further funding for such support activities. 
 
In addition, Globus Connect is quickly diverging from the Globus Toolkit, as detailed in the FAQ. We must focus on supporting the Globus Connect code base, as this is what our subscribers depend on. Supporting and maintaining the open source Globus Toolkit would involve substantial, separate effort, for which no-one has shown a willingness to provide funding.
 
**Why we recommend that current Globus Toolkit users migrate to, and subscribe to, the Globus cloud service**. The Globus cloud service provides more functionality than the open source Globus Toolkit, is adding new capabilities rapidly, and is underpinned by a proven, sustainable business model that will ensure that it persists into the future. Subscribers get high-quality support from the Globus team, an assurance of software longevity, and the satisfaction of supporting a professional team that develops and operates valuable software for the research community. They also get access to capabilities that are superior to those provided by the open source Globus Toolkit: for example, automatic performance optimization, data sharing, specialized storage connectors (e.g., Google Drive, Amazon S3, Ceph, Spectra Logic BlackPearl), data publication, improved security, REST APIs, and powerful management services. The functionality gap between Globus Toolkit and the Globus cloud service will grow even larger as we develop more modern capabilities to support the research data management lifecycle, such as more storage connectors, web-compatible HTTPS+OAuth2 access to storage, metadata handling, data search with access control, and HIPAA compliance. Subscribers are collectively investing in, and helping us develop, these capabilities for the benefit of the broader research community. 
 
Please contact us with any comments, questions, or concerns, at support@globus.org. 

## FAQ (send us more, and check back for updates)

**How can I migrate from the open source Globus Toolkit to the Globus cloud service**? 
We provide documentation and online support, as well as professional services to assist any person or community migrating from Globus Toolkit to the Globus cloud service. We will be delighted to discuss and recommend a migration approach that is best suited to your specific scenario/environment.
 
**Must I subscribe to use the Globus cloud service**? 
While subscription is encouraged and provides access to more capabilities, the Basic - Free option allows for unlimited file transfers between endpoints, offering a free alternative to the file transfer capabilities provided by the open source Globus Toolkit.
 
**How does the Globus cloud service sustainability model work**? 
The mission of the Globus team at the University of Chicago is to provide the best possible software to the scientific community. 
Recognizing that great engineering serves no purpose if the resulting software is not sustainable, three years ago we established a (non-profit) sustainability model for the Globus cloud service that is now proven and working. This model relies on annual subscription fees paid by the research communities who derive value from Globus. More than 65 universities, national facilities, and projects are already subscribers. Many NSF-funded, DOE-funded, and NIH-funded projects in the U.S. include Globus subscriptions in their budgets, as do a number of non-U.S. projects. Subscribers obtain access to premium features and influence on product directions. The Globus cloud service is on a solid path to sustainability, thanks to these subscribers. We are now laser focused on supporting this service, to ensure that it is sustained long into the future.
 
**How is Globus Connect diverging from the open source Globus Toolkit components**? The current Globus Connect Server version 4 uses the open source Globus Toolkit GridFTP, GSI, and MyProxy. However, major changes to Globus Connect, to be released as version 5 later in 2017, will cause it to diverge from those components.
 
With the introduction of the Globus Auth service in February 2016, we began moving away from the old X.509-based security approach provided by GSI and MyProxy to the modern, more secure, web-friendly, OAuth2-based security approach provided by Globus Auth. Globus Connect Server and Globus Connect Personal are being transitioned to Globus Auth’s OAuth2-based security, so MyProxy and GSI will no longer be required. For example, Globus Connect’s version of GridFTP will use Globus Auth instead of GSI, and removing GSI from Globus Connect will substantially reduce its maintenance burden.
 
We are also adding support to Globus Connect for direct access to storage via HTTPS+OAuth2. This HTTPS interface shares much code with Globus Connect’s GridFTP interface, but requires substantial changes to that GridFTP code. Many other planned enhancements to Globus Connect will cause it to diverge even further from the open source Globus Toolkit’s GridFTP.
 
**I am currently running Globus Connect Server (version 4) to connect my storage endpoint to the Globus cloud service. 
What do I need to do**? You simply need to do continue doing routine updates to Globus Connect Server to ensure that you are unaffected by these changes. Later in 2017, we will release Globus Connect Server version 5, which will not depend on the open source Globus Toolkit. Before the end of 2018, you will need to update your Globus Connect Server version 4 to version 5.
 
**Will current Globus endpoints using the open source Globus Toolkit GridFTP (i.e., not Globus Connect) need to migrate to Globus Connect to continue to receive security updates**? 
Yes, they must be migrated by the end of 2018. We plan to provide security updates to the current Globus Connect version 4, and the open source Globus Toolkit components on which it relies (GridFTP server, GSI, and MyProxy), through the end of 2018, in order to give Globus subscribers ample time to migrate to the new Globus Connect version 5. Sites currently using the open source Globus Toolkit GridFTP server can either migrate immediately to the current Globus Connect version 4 and easily update to version 5 when it is available, or wait until Globus Connect version 5 to migrate. 
 
**Can Globus Connect Server version 5 and Globus Toolkit GridFTP be installed on a server at the same time while transitioning to the Globus cloud service**? 
Yes, with the services listening on different ports.
 
**Can you describe what this announcement means for each Globus Toolkit component and speak to the recommended migration path for each**?
* GridFTP server: The Globus Connect software distributed with the Globus cloud service provides all of the functionality of Globus Toolkit GridFTP, and a growing set of additional capabilities as well. We recommend transitioning to Globus Connect and the Globus cloud service for data transfer.
* globus-url-copy (GridFTP client): Transition to using the [Globus CLI](https://docs.globus.org/cli/) or [Python SDK](https://globus-sdk-python.readthedocs.io) to transfer data via the Globus cloud transfer service.
* GSI: Globus Auth provides a more modern, secure, web-friendly, OAuth2-based security approach than the 1990s-era X.509 of GSI. See https://docs.globus.org/api/auth/ for more information.
* GSI-OpenSSH: We will release Globus Auth-based authentication support for SSH later in 2017. Unlike the current GSI-OpenSSH, this will not require replacing your SSH server, but instead is implemented as a PAM module for use with your existing SSH server. Please contact us for more details if you are eager to use this feature.
* MyProxy: MyProxy provides X.509 certificate management that is used with Globus Connect Server version 4. Globus Connect Server version 5 will use Globus Auth for security and MyProxy will not be needed. We recommend transitioning to Globus Auth when Globus Connect Server version 5 is released.. 
* GRAM: The GRAM job submission tool is no longer widely used. We recommend performing remote execution via SSH with Globus Auth, once that is available.
 
**Will the Globus Toolkit RPM and Debian package repositories disappear**? 
At the end of 2018 we plan on shutting down the Globus Toolkit package repositories, which host source and binary packages of the Globus Toolkit.
 
**Will the Globus Toolkit GitHub source repository remain available after 2018**? 
Yes. But the Globus team at the University of Chicago will no longer update it. 
 
**Will source code for Globus Connect be available**? 
Yes. Globus Connect source code will be available to Globus subscribers under a new Globus Community License, which will allow subscribers to review, compile, and enhance Globus Connect.
 

UUID issues for Burp Suite
==========================

When faced with the problem of identifying entities,  many solutions depend on
UUIDs or GUIDs. However, although being unique doesn’t necessarily make these
identifiers unguessable.

This plugin performs a quick analysis on every request sent as part of passive
scanning, so no additional traffic is generated. The plugin has no UI of its
own, and aside from adding it to Burp, there’s no additional configuration
necessary, it just works.

In case of UUIDs above version 2, it just adds an information-level issue.
However in case of version 1 and 2, a medium severity issue is added, along
with the information that can be extracted from the UUID itself.

[Read more about this plugin in our blog post][1]

Building
--------

Execute `ant`, and you'll have the plugin ready in `burp-uuid.jar`

Dependencies
------------

 - JDK 1.8+ (tested on OpenJDK 8, Debian/Ubuntu package: `openjdk-8-jdk`)
 - Apache ANT (Debian/Ubuntu package: `ant`)

License
-------

The whole project is available under MIT license, see `LICENSE.txt`.

  [1]: https://blog.silentsignal.eu/2017/02/17/not-so-unique-snowflakes/

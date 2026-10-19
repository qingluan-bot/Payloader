// 产品别名词典与归一派生（v2.0.2 治理 A5）：四源 CPE/名称/描述 → 统一 canonical 产品数组。
// 词典只收真实产品（vendor + 产品名 + 中文名多别名），匹配词边界大小写不敏感；
// 未命中词典的 CPE 保留 vendor:product 原键（反转义 `\/`），保证信息不丢失。

const P = (canonical, aliases) => ({ canonical, aliases });

// 内置产品别名词典（canonical 大小写为展示名；aliases 全部小写匹配）。
// 收录原则：真实存在、EXP 语料高频（NVD CPE / EDB 标题 / 护网季国内厂商漏洞）。
export const PRODUCT_ALIASES = [
  // ---- Web 服务器 / 反向代理 ----
  P('Nginx', ['nginx', 'ngx_http']),
  P('OpenResty', ['openresty']),
  P('Apache HTTP Server', ['httpd', 'apache http server', 'apache httpd']),
  P('Apache Tomcat', ['tomcat', 'apache tomcat']),
  P('Microsoft IIS', ['iis', 'internet information services', 'internet information server']),
  P('HAProxy', ['haproxy']),
  P('Caddy', ['caddy']),
  P('Lighttpd', ['lighttpd']),
  P('GoAhead', ['goahead']),
  P('Squid', ['squid']),
  P('Resin', ['cauchoresin', 'caucho resin', 'resin']),
  // ---- 中间件 / 应用服务器 ----
  P('Oracle WebLogic', ['weblogic', 'oracle weblogic']),
  P('IBM WebSphere', ['websphere', 'ibm websphere']),
  P('JBoss', ['jboss', 'jboss as', 'jboss eap']),
  P('WildFly', ['wildfly']),
  P('GlassFish', ['glassfish']),
  P('Jetty', ['jetty', 'eclipse jetty']),
  P('Undertow', ['undertow']),
  P('Apache Solr', ['solr', 'apache solr']),
  P('Elasticsearch', ['elasticsearch', 'elastic']),
  P('Logstash', ['logstash']),
  P('Kibana', ['kibana']),
  P('RabbitMQ', ['rabbitmq']),
  P('Apache Kafka', ['kafka', 'apache kafka']),
  P('Apache ActiveMQ', ['activemq', 'apache activemq']),
  P('Apache RocketMQ', ['rocketmq', 'apache rocketmq']),
  P('Nacos', ['alibaba nacos', 'nacos']),
  P('Apache Dubbo', ['dubbo', 'apache dubbo']),
  P('ZooKeeper', ['zookeeper', 'apache zookeeper']),
  P('etcd', ['etcd']),
  P('HashiCorp Consul', ['consul', 'hashicorp consul']),
  P('MinIO', ['minio']),
  P('Apache Hadoop', ['hadoop', 'apache hadoop']),
  P('Apache Spark', ['apache spark']),
  P('Apache Hive', ['apache hive']),
  P('Apache NiFi', ['nifi', 'apache nifi']),
  P('Apache Airflow', ['airflow', 'apache airflow']),
  P('Apache Flink', ['flink', 'apache flink']),
  P('Apache SkyWalking', ['skywalking', 'apache skywalking']),
  P('ClickHouse', ['clickhouse']),
  P('InfluxDB', ['influxdb']),
  // ---- Java 生态组件 ----
  P('Apache Struts', ['struts', 'struts2', 'apache struts', 'org.apache.struts2']),
  P('Spring Framework', ['spring framework', 'springframework', 'org.springframework']),
  P('Spring Boot', ['spring boot', 'springboot', 'org.springframework.boot']),
  P('Spring Cloud', ['spring cloud', 'springcloud', 'org.springframework.cloud']),
  P('Spring Security', ['spring security', 'org.springframework.security']),
  P('Spring Data', ['spring data']),
  P('ThinkPHP', ['thinkphp', 'topthink']),
  P('Fastjson', ['fastjson', 'com.alibaba.fastjson']),
  P('Jackson', ['jackson', 'jackson-databind', 'fasterxml jackson', 'com.fasterxml.jackson']),
  P('XStream', ['xstream']),
  P('Apache Log4j', ['log4j', 'log4j2', 'apache log4j', 'org.apache.logging.log4j']),
  P('Logback', ['logback', 'ch.qos.logback']),
  P('Apache Shiro', ['shiro', 'apache shiro', 'org.apache.shiro']),
  P('Hibernate', ['hibernate', 'org.hibernate']),
  P('MyBatis', ['mybatis', 'org.mybatis']),
  P('Netty', ['netty', 'io.netty']),
  P('Apache Axis2', ['axis2', 'apache axis2']),
  P('Apollo Config', ['apollo config', 'ctrip apollo']),
  P('XXL-JOB', ['xxl-job', 'xxljob']),
  // ---- 开发协作 / DevOps ----
  P('WordPress', ['wordpress', 'wp-content', 'wp-admin']),
  P('Joomla', ['joomla']),
  P('Drupal', ['drupal']),
  P('TYPO3', ['typo3']),
  P('phpBB', ['phpbb']),
  P('vBulletin', ['vbulletin']),
  P('Atlassian Confluence', ['confluence', 'atlassian confluence']),
  P('Atlassian Jira', ['jira', 'atlassian jira']),
  P('Atlassian Bitbucket', ['bitbucket', 'atlassian bitbucket']),
  P('Atlassian Bamboo', ['atlassian bamboo']),
  P('Atlassian Crowd', ['atlassian crowd']),
  P('GitLab', ['gitlab']),
  P('Gitea', ['gitea']),
  P('Gogs', ['gogs']),
  P('Gitee', ['gitee']),
  P('Jenkins', ['jenkins', 'hudson']),
  P('JetBrains TeamCity', ['teamcity']),
  P('Sonatype Nexus', ['nexus repository', 'nexus repository manager', 'sonatype nexus']),
  P('SonarQube', ['sonarqube']),
  P('JFrog Artifactory', ['artifactory', 'jfrog artifactory']),
  P('Harbor', ['harbor', 'goharbor']),
  P('Kubernetes', ['kubernetes', 'k8s']),
  P('Docker', ['docker']),
  P('HashiCorp Vault', ['hashicorp vault']),
  P('JumpServer', ['jumpserver']),
  P('禅道 ZenTao', ['zentao', '禅道']),
  // ---- 监控运维 ----
  P('Zabbix', ['zabbix']),
  P('Grafana', ['grafana']),
  P('Prometheus', ['prometheus']),
  P('Nagios', ['nagios']),
  P('SolarWinds', ['solarwinds']),
  P('PRTG', ['prtg']),
  // ---- 数据库 ----
  P('MySQL', ['mysql']),
  P('MariaDB', ['mariadb']),
  P('PostgreSQL', ['postgresql', 'postgres']),
  P('MongoDB', ['mongodb']),
  P('Redis', ['redis']),
  P('Memcached', ['memcached']),
  P('Microsoft SQL Server', ['microsoft sql server', 'mssql', 'sql server']),
  P('Oracle Database', ['oracle database', 'oracle db']),
  P('达梦 DM', ['dameng', '达梦']),
  P('人大金仓 Kingbase', ['kingbase', '人大金仓']),
  P('OceanBase', ['oceanbase']),
  P('TiDB', ['tidb']),
  P('phpMyAdmin', ['phpmyadmin']),
  P('Adminer', ['adminer']),
  // ---- PHP / Web 框架与 CMS ----
  P('PHP', ['php', 'php-fpm']),
  P('Yii', ['yii']),
  P('Laravel', ['laravel']),
  P('CodeIgniter', ['codeigniter']),
  P('CakePHP', ['cakephp']),
  P('Symfony', ['symfony']),
  P('Zend Framework', ['zend framework', 'zendframework', 'laminas']),
  P('Django', ['django']),
  P('Flask', ['flask']),
  P('Ruby on Rails', ['ruby on rails']),
  P('Node.js', ['node.js', 'nodejs']),
  P('Discuz', ['discuz']),
  P('Typecho', ['typecho']),
  P('Z-BlogPHP', ['z-blog', 'zblog']),
  P('Emlog', ['emlog']),
  P('DedeCMS', ['dedecms', '织梦']),
  P('EmpireCMS', ['empirecms', '帝国cms']),
  P('PHPCMS', ['phpcms']),
  P('PbootCMS', ['pbootcms']),
  P('ThinkCMF', ['thinkcmf']),
  P('MacCMS', ['maccms', '苹果cms']),
  P('SeaCMS', ['seacms', '海洋cms']),
  P('MetInfo', ['metinfo']),
  P('Nextcloud', ['nextcloud']),
  P('ownCloud', ['owncloud']),
  P('Seafile', ['seafile']),
  P('Mattermost', ['mattermost']),
  P('Rocket.Chat', ['rocket.chat']),
  P('Odoo', ['odoo']),
  P('SugarCRM', ['sugarcrm']),
  // ---- 邮件 / 即时通讯 / 远程工具 ----
  P('Coremail', ['coremail']),
  P('亿邮 eYou', ['eyou', '亿邮']),
  P('TurboMail', ['turbomail']),
  P('Microsoft Exchange', ['microsoft exchange', 'exchange server']),
  P('Microsoft SharePoint', ['sharepoint', 'microsoft sharepoint']),
  P('Zimbra', ['zimbra', 'synacor zimbra']),
  P('向日葵 Sunlogin', ['sunlogin', '向日葵']),
  P('ToDesk', ['todesk']),
  P('TeamViewer', ['teamviewer']),
  // ---- 网络与安全设备 / 厂商 ----
  P('F5 BIG-IP', ['f5 big-ip', 'big-ip', 'bigip', 'f5']),
  P('Citrix NetScaler', ['netscaler', 'citrix netscaler', 'citrix adc']),
  P('Fortinet FortiOS', ['fortios', 'fortigate', 'fortinet']),
  P('PAN-OS', ['pan-os', 'panos', 'palo alto']),
  P('Ivanti', ['ivanti', 'pulse secure', 'pulse connect secure']),
  P('Juniper', ['juniper', 'junos']),
  P('Cisco', ['cisco']),
  P('MikroTik RouterOS', ['routeros', 'mikrotik']),
  P('TP-Link', ['tp-link', 'tplink']),
  P('D-Link', ['d-link', 'dlink']),
  P('NETGEAR', ['netgear']),
  P('Tenda', ['tenda']),
  P('TOTOLink', ['totolink']),
  P('ZTE', ['zte', '中兴']),
  P('华为 Huawei', ['huawei', '华为']),
  P('新华三 H3C', ['h3c', '新华三']),
  P('锐捷 Ruijie', ['ruijie', '锐捷']),
  P('深信服 Sangfor', ['sangfor', '深信服']),
  P('奇安信 QiAnXin', ['qianxin', '奇安信']),
  P('绿盟 NSFOCUS', ['nsfocus', '绿盟']),
  P('天融信 TopSec', ['topsec', '天融信']),
  P('启明星辰 Venus', ['venustech', '启明星辰']),
  P('安恒信息 DBAPPSecurity', ['dbappsecurity', 'dbapp', '安恒']),
  P('大华 Dahua', ['dahua', '大华']),
  P('海康威视 Hikvision', ['hikvision', '海康威视', 'hik']),
  P('天地伟业 Tiandy', ['tiandy', '天地伟业']),
  P('宇视 Uniview', ['uniview', '宇视']),
  P('VMware vCenter', ['vcenter', 'vmware vcenter']),
  P('VMware ESXi', ['esxi', 'vmware esxi']),
  P('VMware Workspace ONE', ['workspace one', 'vmware workspace']),
  // ---- 应用系统（护网季国内高频）----
  P('用友 Yonyou', ['yonyou', 'ufida', '用友']),
  P('致远 Seeyon', ['seeyon', '致远']),
  P('泛微 Weaver', ['weaver e-cology', 'e-cology', '泛微']),
  P('通达 OA', ['tongda', '通达oa']),
  P('蓝凌 Landray', ['landray', '蓝凌']),
  P('帆软 FanRuan', ['fanruan', '帆软', 'finereport', 'finebi']),
  P('万户 OA', ['wanhu', 'ezoffice', '万户']),
  P('金蝶 Kingdee', ['kingdee', '金蝶']),
  P('亿赛通 EsafeNet', ['esafenet', '亿赛通']),
  P('齐治堡垒机', ['qizhi', '齐治']),
  P('宝塔面板', ['宝塔', 'baota', 'aapanel', 'bt panel']),
  P('魔方财务', ['魔方财务', 'zjmf', 'idcsmart']),
  P('JeeSite', ['jeesite']),
  P('若依 RuoYi', ['ruoyi', '若依']),
  P('ThinkSNS', ['thinksns']),
  // ---- 基础组件 ----
  P('OpenSSH', ['openssh']),
  P('OpenSSL', ['openssl']),
  P('OpenVPN', ['openvpn']),
  P('Samba', ['samba']),
  P('vsftpd', ['vsftpd']),
  P('ProFTPD', ['proftpd']),
  P('Pure-FTPd', ['pure-ftpd']),
  P('Postfix', ['postfix']),
  P('Dovecot', ['dovecot']),
  P('Exim', ['exim']),
  P('ISC BIND', ['isc bind', 'bind9']),
  P('dnsmasq', ['dnsmasq']),
  P('Asterisk', ['asterisk']),
  P('FreeSWITCH', ['freeswitch']),
  P('FreePBX', ['freepbx']),
  P('3CX', ['3cx']),
  P('Cloudflare', ['cloudflare']),
  P('SAP NetWeaver', ['netweaver', 'sap netweaver']),
  P('Adobe ColdFusion', ['coldfusion', 'adobe coldfusion']),
  P('PeopleSoft', ['peoplesoft']),
  P('Google Chrome', ['google chrome', 'chrome']),
  P('Firefox', ['firefox', 'mozilla firefox']),
];

// lowercase 别名 → canonical（构建一次，module 级缓存）
const ALIAS_INDEX = (() => {
  const index = new Map();
  for (const entry of PRODUCT_ALIASES) {
    index.set(entry.canonical.toLowerCase(), entry.canonical);
    for (const alias of entry.aliases) {
      if (!index.has(alias)) index.set(alias, entry.canonical);
    }
  }
  return index;
})();

const escapeRegExp = value => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
// 纯 ASCII 别名可用词边界（防 express/struts 子串误报）；含 CJK 的别名只能包含匹配。
// 边界集含 `_`：cpe 复合键（oracle:mysql_enterprise_monitor）中的 mysql 不派生裸 'MySQL'，
// 否则产品关联管线会把 MySQL 载荷误挂到 Struts 等无关条目（真实翻车案例）。
const isAsciiWord = value => /^[a-z0-9][a-z0-9_.+:/-]*$/i.test(value);

const aliasPatternCache = new Map();
const matchInText = (text, alias) => {
  const lower = text.toLowerCase();
  if (!lower.includes(alias)) return false;
  if (!isAsciiWord(alias)) return true;
  let pattern = aliasPatternCache.get(alias);
  if (!pattern) {
    pattern = new RegExp(`(?<![a-z0-9_])${escapeRegExp(alias)}(?![a-z0-9_])`, 'i');
    aliasPatternCache.set(alias, pattern);
  }
  return pattern.test(text);
};

// 词在文本中是否独立出现（与 deriveProducts 文本通道同一边界语义）。
// 导出给关联管线复核已落库 products——复合键误派生的裸词（mysql_enterprise_monitor→MySQL）
// 在全文中从未独立出现，据此剔除，不重算全表即可净化关联。
export const productStandsAlone = (word, text) => {
  const value = String(word ?? '').trim().toLowerCase();
  if (!value || !text) return false;
  return matchInText(String(text), value);
};

// CPE 'vendor:product'（可含 `\/` 转义）→ canonical 或原键
const cpeCanonicalOf = rawValue => {
  const value = String(rawValue ?? '').replace(/\\\//g, '/').trim().toLowerCase();
  if (!value) return '';
  if (!value.includes(':')) return ALIAS_INDEX.get(value) || value;
  const vendor = value.split(':')[0];
  const product = value.slice(vendor.length + 1);
  return ALIAS_INDEX.get(value) || ALIAS_INDEX.get(product) || `${vendor}:${product}`;
};

// 统一派生入口：{cpeProducts, name, description, affected} → 去重排序 canonical 数组。
// 词典命中优先，未命中词典的 CPE 原键殿后；cap 12。
export const deriveProducts = ({ cpeProducts = [], name = '', description = '', affected = '' } = {}) => {
  const canonicalHits = new Set();
  const rawKeys = new Set();
  for (const raw of Array.isArray(cpeProducts) ? cpeProducts : []) {
    const resolved = cpeCanonicalOf(raw);
    if (!resolved) continue;
    if (ALIAS_INDEX.has(resolved.toLowerCase())) canonicalHits.add(resolved);
    else rawKeys.add(resolved);
  }
  const text = `${name}\n${description}\n${affected}`;
  if (text.trim()) {
    for (const [alias, canonical] of ALIAS_INDEX) {
      if (alias.length < 2) continue;
      if (canonicalHits.has(canonical) || rawKeys.has(canonical)) continue;
      if (matchInText(text, alias)) canonicalHits.add(canonical);
    }
  }
  return [...canonicalHits].sort((a, b) => a.localeCompare(b))
    .concat([...rawKeys].sort((a, b) => a.localeCompare(b)))
    .slice(0, 12);
};

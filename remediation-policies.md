|Sr. No.|  Service	|Policy Id					|Policy Title|
|-------|-----------|---------------------------|----------------------------------------------------------------|
|1		|IAM		|IAMPasswordUpperCaseLetter	|Ensure IAM password policy requires at least one uppercase letter|
|2		|IAM		|IAMRequireLowercaseLetter	|Ensure IAM password policy require at least one lowercase letter|
|3		|IAM		|IAMPasswordRequireSymbols	|Ensure IAM password policy require at least one symbol|
|4		|IAM		|IAMPasswordRequireNumber	|Ensure IAM password policy require at least one number|
|5		|IAM		|IAMMinPasswordLength		|Ensure IAM password policy requires minimum length of 14 or greater|
|6		|IAM		|IAMPasswordReusePrevention	|Ensure IAM password policy prevents password reuse|
|7		|IAM		|IAMExpirePasswords			|Ensure IAM password policy expires passwords within 90 days or less|
|8		|CloudTrail	|CTMultiRegionTrail			|Ensure CloudTrail is enabled in all regions|
|9		|CloudTrail	|LogFileValidationEnabled	|Ensure CloudTrail log file validation is enabled|
|10		|KMS		|KMSRotationEnabled			|Ensure rotation for customer created CMKs is enabled|
|11		|S3			|S3VersioningEnabled		|Ensure S3 buckets have versioning enabled|
|12		|S3			|S3notPublictoInternet		|Ensure that your AWS S3 buckets are not publicly exposed to the Internet|
|13		|S3			|S3notPublicRead			|Ensure AWS S3 buckets do not allow public READ access|
|14		|S3			|S3notPublicReadACP			|Ensure AWS S3 buckets do not allow public READ_ACP access|
|15		|S3			|S3notPublicWrite			|Ensure AWS S3 buckets do not allow public WRITE access|
|16		|S3			|S3notPublicWriteACP		|Ensure AWS S3 buckets do not allow public WRITE_ACP access|
|17		|S3			|S3EncryptionEnabled		|Ensure Amazon S3 buckets have Default Encryption feature enabled|
|18		|S3			|S3bucketNoPublicAAUFull	|Ensure S3 buckets do not allow FULL_CONTROL access to AWS authenticated users via S3 ACLs|
|19		|S3			|S3bucketNoPublicAAURead	|Ensure S3 buckets do not allow READ access to AWS authenticated users through ACLs|
|20		|S3			|S3bucketNoPublicAAUReadACP	|Ensure AWS S3 buckets do not allow READ_ACP access to AWS authenticated users using ACLs|
|21		|S3			|S3bucketNoPublicAAUWrite	|Ensure S3 buckets do not allow WRITE access to AWS authenticated users through S3 ACLs|
|22		|S3			|S3bucketNoPublicAAUWriteACP|Ensure S3 buckets do not allow WRITE_ACP access to AWS authenticated users using S3 ACLs|
|23		|Redshift	|RedShiftNotPublic			|Ensure Redshift clusters are not publicly accessible to minimize security risks|
|24		|Redshift	|RedShiftVersionUpgrade		|Ensure Version Upgrade is enabled for Redshift clusters to automatically receive upgrades during the maintenance window|
|25		|Redshift	|RedShiftAutomatedSnapshot	|Ensure that retention period is enabled for Amazon Redshift automated snapshots|
|26		|Classic Load Balancer	|ClassicLBConnDraining	|Ensure Connection Draining is enabled for your AWS Classic Load Balancer|
|27		|Application Load Balancer	|AppLBDeletionProtection	|Ensure Deletion Protection feature is enabled for your AWS Application load balancers to follow security best practices|
|28		|Network Load Balancer	|NetworkLBDeletionProtection	|Ensure Deletion Protection feature is enabled for your AWS Network load balancers to follow security best practices|
|29		|Kinesis	|KinesisEnhancedMonitoring	|Ensure enhanced monitoring is enabled for your AWS Kinesis streams using shard-level metrics|
|30		|RDS Cluster	|AuroraDeleteProtection	|Ensure that Deletion Protection feature is enabled for RDS Aurora Cluster|
|31		|RDS Cluster	|AuroraServerlessDeleteProtection	|Ensure that Deletion Protection feature is enabled for RDS Aurora MySQL Serverless Cluster|
|32		|RDS Cluster	|AuroraPostgresServerlessDeleteProtection	|Ensure that Deletion Protection feature is enabled for RDS Aurora Postgres Serverless Cluster|
|33		|RDS Cluster	|AuroraBackup	|Ensure backup retention policy is set for RDS Aurora Cluster|
|34		|RDS Cluster	|AuroraBackupTerm	|Ensure that sufficient backup retention period is applied to RDS Aurora Cluster|
|35		|RDS Cluster	|AuroraServerlessBackupTerm	|Ensure that sufficient backup retention period is applied to RDS Aurora MySQL Serverless Cluster|
|36		|RDS Cluster	|AuroraPostgresServerlessBackupTerm	|Ensure that sufficient backup retention period is applied to RDS Aurora Postgres Serverless Cluster|
|37		|RDS Cluster	|AuroraCopyTagsToSnapshot	|Ensure that Copy Tags to Snapshots feature is enabled for RDS Aurora Cluster|
|38		|RDS Cluster	|AuroraServerlessCopyTagsToSnapshot	|Ensure that Copy Tags to Snapshots feature is enabled for RDS Aurora MySQL Serverless Cluster|
|39		|RDS Cluster	|AuroraPostgresServerlessCopyTagsToSnapshot	|Ensure that Copy Tags to Snapshots feature is enabled for RDS Aurora Postgres Serverless Cluster|
|40		|RDS Cluster	|AuroraServerlessScalingAutoPause	|Ensure that AutoPause feature is enabled for RDS Aurora MySQL Serverless Cluster|
|41		|RDS Cluster	|AuroraPostgresServerlessScalingAutoPause	|Ensure that AutoPause feature is enabled for RDS Aurora Postgres Serverless Cluster|
|42		|RDS Instance	|SQLPerformanceInsights	|Ensure Performance Insights feature is enabled for RDS Postgre Instances|
|43		|RDS Instance	|MariadbPerformanceInsights	|Ensure Performance Insights feature is enabled for RDS MariaDB Instances|
|44		|RDS Instance	|OraclePerformanceInsights	|Ensure Performance Insights feature is enabled for RDS Oracle Instances|
|45		|RDS Instance	|SQLServerPerformanceInsights	|Ensure Performance Insights feature is enabled for RDS SQL Server Instances|
|46		|RDS Instance	|AuroraInstancePerformanceInsights	|Ensure Performance Insights feature is enabled for Aurora SQL Instances|
|47		|RDS Instance	|SQLBackup	|Ensure backup retention policy is set for RDS Postgre Instances|
|48		|RDS Instance	|SQLBackupTerm	|Ensure that sufficient backup retention period is applied to RDS Postgre Instances|
|49		|RDS Instance	|MariadbBackup	|Ensure backup retention policy is set for RDS MariaDB Instances|
|50		|RDS Instance	|MariadbBackupTerm	|Ensure that sufficient backup retention period is applied to RDS MariaDB Instances|
|51		|RDS Instance	|OracleBackup	|Ensure backup retention policy is set for RDS Oracle Instances|
|52		|RDS Instance	|OracleBackupTerm	|Ensure that sufficient backup retention period is applied to RDS Oracle Instances|
|53		|RDS Instance	|SQLServerBackup	|Ensure backup retention policy is set for RDS SQL Server Instance|
|54		|RDS Instance	|SQLServerBackupTerm	|Ensure that sufficient backup retention period is applied to RDS SQL Server Instances|
|55		|RDS Instance	|SQLCopyTagsToSnapshot	|Ensure that Copy Tags to Snapshots feature is enabled for RDS Postgre Instances|
|56		|RDS Instance	|MariadbCopyTagsToSnapshot	|Ensure that Copy Tags to Snapshots feature is enabled for RDS MariaDB Instances|
|57		|RDS Instance	|OracleCopyTagsToSnapshot	|Ensure that Copy Tags to Snapshots feature is enabled for RDS Oracle Instances|
|58		|RDS Instance	|SQLServerCopyTagsToSnapshot	|Ensure that Copy Tags to Snapshots feature is enabled for RDS SQL Server Instances|
|59		|RDS Instance	|SQLDeletionProtection	|Ensure Deletion Protection feature is enabled for RDS Postgre Instances|
|60		|RDS Instance	|MariadbDeletionProtection	|Ensure Deletion Protection feature is enabled for RDS MariaDB Instances|
|61		|RDS Instance	|OracleDeletionProtection	|Ensure Deletion Protection feature is enabled for AWS RDS Oracle Instances|
|62		|RDS Instance	|SQLServerDeletionProtection	|Ensure Deletion Protection feature is enabled for RDS SQL Server Instances|
|63		|RDS Instance	|SQLPrivateInstance	|Ensure that public access is not given to RDS Postgre Instance|
|64		|RDS Instance	|MariadbPrivateInstance	|Ensure that public access is not given to RDS MariaDB Instance|
|65		|RDS Instance	|OraclePrivateInstance	|Ensure that public access is not given to RDS Oracle Instances|
|66		|RDS Instance	|SQLServerPrivateInstance	|Ensure that public access is not given to RDS SQL Server Instances|
|67		|RDS Instance	|AuroraInstancePrivateInstance	|Ensure that public access is not given to RDS Aurora SQL Instances|
|68		|RDS Instance	|SQLVersionUpgrade	|Ensure Auto Minor Version Upgrade feature is Enabled for RDS Postgre Instances|
|69		|RDS Instance	|MariadbVersionUpgrade	|Ensure Auto Minor Version Upgrade feature is Enabled for RDS MariaDB Instances|
|70		|RDS Instance	|OracleVersionUpgrade	|Ensure Auto Minor Version Upgrade feature is Enabled for RDS Oracle Instances|
|71		|RDS Instance	|SQLServerVersionUpgrade	|Ensure Auto Minor Version Upgrade feature is Enabled for RDS SQL Server Instances|
|72		|RDS Instance	|AuroraInstanceVersionUpgrade	|Ensure Auto Minor Version Upgrade feature is Enabled for RDS Aurora SQL Instances|
|73		|RDS Instance	|SQLMultiAZEnabled	|Ensure Multi-AZ feature is Enabled for RDS SQL Instance|
|74		|RDS Instance	|MariadbMultiAZEnabled	|Ensure Multi-AZ feature is Enabled for RDS MariaDB Instance|
|75		|RDS Instance	|OracleMultiAZEnabled	|Ensure Multi-AZ feature is Enabled for RDS Oracle Instances|
|76		|RDS Instance	|SQLServerMultiAZEnabled	|Ensure Multi-AZ feature is Enabled for RDS SQL Server Instances|
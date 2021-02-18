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
|23		|S3 	|S3TransferAccelerateConfig 	|Ensure that Amazon S3 buckets use Transfer Acceleration feature for faster data transfers|
|24		|S3 	|S3busketpublicaccess	|Ensure that S3 buckets are not publicly accessible|
|25		|Redshift	|RedShiftNotPublic			|Ensure Redshift clusters are not publicly accessible to minimize security risks|
|26		|Redshift	|RedShiftVersionUpgrade		|Ensure Version Upgrade is enabled for Redshift clusters to automatically receive upgrades during the maintenance window|
|27		|Redshift	|RedShiftAutomatedSnapshot	|Ensure that retention period is enabled for Amazon Redshift automated snapshots|
|28		|Classic Load Balancer	|ClassicLBConnDraining	|Ensure Connection Draining is enabled for your AWS Classic Load Balancer|
|29		|Application Load Balancer	|AppLBDeletionProtection	|Ensure Deletion Protection feature is enabled for your AWS Application load balancers to follow security best practices|
|30		|Network Load Balancer	|NetworkLBDeletionProtection	|Ensure Deletion Protection feature is enabled for your AWS Network load balancers to follow security best practices|
|31		|Kinesis	|KinesisEnhancedMonitoring	|Ensure enhanced monitoring is enabled for your AWS Kinesis streams using shard-level metrics|
|32		|RDS Cluster	|AuroraDeleteProtection	|Ensure that Deletion Protection feature is enabled for RDS Aurora Cluster|
|33		|RDS Cluster	|AuroraServerlessDeleteProtection	|Ensure that Deletion Protection feature is enabled for RDS Aurora MySQL Serverless Cluster|
|34		|RDS Cluster	|AuroraPostgresServerlessDeleteProtection	|Ensure that Deletion Protection feature is enabled for RDS Aurora PostgreSQL Serverless Cluster|
|35		|RDS Cluster	|AuroraBackup	|Ensure backup retention policy is set for RDS Aurora Cluster|
|36		|RDS Cluster	|AuroraBackupTerm	|Ensure that sufficient backup retention period is applied to RDS Aurora Cluster|
|37		|RDS Cluster	|AuroraServerlessBackupTerm	|Ensure that sufficient backup retention period is applied to RDS Aurora MySQL Serverless Cluster|
|38		|RDS Cluster	|AuroraPostgresServerlessBackupTerm	|Ensure that sufficient backup retention period is applied to RDS Aurora PostgreSQL Serverless Cluster|
|39		|RDS Cluster	|AuroraCopyTagsToSnapshot	|Ensure that Copy Tags to Snapshots feature is enabled for RDS Aurora Cluster|
|40		|RDS Cluster	|AuroraServerlessCopyTagsToSnapshot	|Ensure that Copy Tags to Snapshots feature is enabled for RDS Aurora MySQL Serverless Cluster|
|41		|RDS Cluster	|AuroraPostgresServerlessCopyTagsToSnapshot	|Ensure that Copy Tags to Snapshots feature is enabled for RDS Aurora PostgreSQL Serverless Cluster|
|42		|RDS Cluster	|AuroraServerlessScalingAutoPause	|Ensure that AutoPause feature is enabled for RDS Aurora MySQL Serverless Cluster|
|43		|RDS Cluster	|AuroraPostgresServerlessScalingAutoPause	|Ensure that AutoPause feature is enabled for RDS Aurora PostgreSQL Serverless Cluster|
|44		|RDS Cluster	|CloudwatchLogsExports 	|Ensure Log Exports feature is enabled for RDS Aurora MySQL Serverless Cluster|
|45		|RDS Cluster	|AuroralogExport	|Ensure Log Exports feature is enabled for Aurora cluster|
|46		|RDS Cluster	|AuroraIAMAuthEnabled	|Ensure IAM Database Authentication feature is enabled for RDS Aurora Cluster|
|47		|RDS Instance	|SQLPerformanceInsights	|Ensure Performance Insights feature is enabled for RDS PostgreSQL Instances|
|48		|RDS Instance	|MariadbPerformanceInsights	|Ensure Performance Insights feature is enabled for RDS MariaDB Instances|
|49		|RDS Instance	|OraclePerformanceInsights	|Ensure Performance Insights feature is enabled for RDS Oracle Instances|
|50		|RDS Instance	|SQLServerPerformanceInsights	|Ensure Performance Insights feature is enabled for RDS SQL Server Instances|
|51		|RDS Instance	|AuroraInstancePerformanceInsights	|Ensure Performance Insights feature is enabled for Aurora SQL Instances|
|52		|RDS Instance	|SQLBackup	|Ensure backup retention policy is set for RDS PostgreSQL Instances|
|53		|RDS Instance	|SQLBackupTerm	|Ensure that sufficient backup retention period is applied to RDS PostgreSQL Instances|
|54		|RDS Instance	|MariadbBackup	|Ensure backup retention policy is set for RDS MariaDB Instances|
|55		|RDS Instance	|MariadbBackupTerm	|Ensure that sufficient backup retention period is applied to RDS MariaDB Instances|
|56		|RDS Instance	|OracleBackup	|Ensure backup retention policy is set for RDS Oracle Instances|
|57		|RDS Instance	|OracleBackupTerm	|Ensure that sufficient backup retention period is applied to RDS Oracle Instances|
|58		|RDS Instance	|SQLServerBackup	|Ensure backup retention policy is set for RDS SQL Server Instance|
|59		|RDS Instance	|SQLServerBackupTerm	|Ensure that sufficient backup retention period is applied to RDS SQL Server Instances|
|60		|RDS Instance	|SQLCopyTagsToSnapshot	|Ensure that Copy Tags to Snapshots feature is enabled for RDS PostgreSQL Instances|
|61		|RDS Instance	|MariadbCopyTagsToSnapshot	|Ensure that Copy Tags to Snapshots feature is enabled for RDS MariaDB Instances|
|62		|RDS Instance	|OracleCopyTagsToSnapshot	|Ensure that Copy Tags to Snapshots feature is enabled for RDS Oracle Instances|
|63		|RDS Instance	|SQLServerCopyTagsToSnapshot	|Ensure that Copy Tags to Snapshots feature is enabled for RDS SQL Server Instances|
|64		|RDS Instance	|SQLDeletionProtection	|Ensure Deletion Protection feature is enabled for RDS PostgreSQL Instances|
|65		|RDS Instance	|MariadbDeletionProtection	|Ensure Deletion Protection feature is enabled for RDS MariaDB Instances|
|66		|RDS Instance	|OracleDeletionProtection	|Ensure Deletion Protection feature is enabled for AWS RDS Oracle Instances|
|67		|RDS Instance	|SQLServerDeletionProtection	|Ensure Deletion Protection feature is enabled for RDS SQL Server Instances|
|68		|RDS Instance	|SQLPrivateInstance	|Ensure that public access is not given to RDS PostgreSQL Instance|
|69		|RDS Instance	|MariadbPrivateInstance	|Ensure that public access is not given to RDS MariaDB Instance|
|70		|RDS Instance	|OraclePrivateInstance	|Ensure that public access is not given to RDS Oracle Instances|
|71		|RDS Instance	|SQLServerPrivateInstance	|Ensure that public access is not given to RDS SQL Server Instances|
|72		|RDS Instance	|AuroraInstancePrivateInstance	|Ensure that public access is not given to RDS Aurora SQL Instances|
|73		|RDS Instance	|SQLVersionUpgrade	|Ensure Auto Minor Version Upgrade feature is Enabled for RDS PostgreSQL Instances|
|74		|RDS Instance	|MariadbVersionUpgrade	|Ensure Auto Minor Version Upgrade feature is Enabled for RDS MariaDB Instances|
|75		|RDS Instance	|OracleVersionUpgrade	|Ensure Auto Minor Version Upgrade feature is Enabled for RDS Oracle Instances|
|76		|RDS Instance	|SQLServerVersionUpgrade	|Ensure Auto Minor Version Upgrade feature is Enabled for RDS SQL Server Instances|
|77		|RDS Instance	|AuroraInstanceVersionUpgrade	|Ensure Auto Minor Version Upgrade feature is Enabled for RDS Aurora SQL Instances|
|78		|RDS Instance	|SQLMultiAZEnabled	|Ensure Multi-AZ feature is Enabled for RDS SQL Instance|
|79		|RDS Instance	|MariadbMultiAZEnabled	|Ensure Multi-AZ feature is Enabled for RDS MariaDB Instance|
|80		|RDS Instance	|OracleMultiAZEnabled	|Ensure Multi-AZ feature is Enabled for RDS Oracle Instances|
|81		|RDS Instance	|SQLServerMultiAZEnabled	|Ensure Multi-AZ feature is Enabled for RDS SQL Server Instances|
|82		|RDS Instance	|MySQLlogExport 	|Ensure Log Exports feature is enabled for RDS MySQL Instance|
|83		|RDS Instance	|MariadblogExport	|Ensure Log Exports feature is enabled for RDS Mariadb Instance|
|84		|RDS Instance	|OraclelogExport	|Ensure Log Exports feature is enabled for Oracle instances|
|85		|RDS Instance	|MySQLVersionUpgrade	|Ensure Auto Minor Version Upgrade feature is Enabled for RDS MySQL Instances|
|86		|RDS Instance	|MySQLBackup	|Ensure backup retention policy is set for RDS MySQL Instances|
|87		|RDS Instance	|MySQLCopyTagsToSnapshot	|Ensure that Copy Tags to Snapshots feature is enabled for RDS MySQL Instances|
|88		|RDS Instance	|MySQLDeletionProtection	|Ensure Deletion Protection feature is enabled for RDS MySQL Instances|
|89		|RDS Instance	|MySQLPerformanceInsights	|Ensure Performance Insights feature is enabled for RDS MySQL Instances|
|90		|RDS Instance	|MySQLPrivateInstance	|Ensure that public access is not given to RDS MySQL Instance|
|91		|RDS Instance	|MySQLMultiAZEnabled	|Ensure Multi-AZ feature is Enabled for RDS MySQL Instance|
|92		|RDS Instance	|MySQLBackupTerm	|Ensure that sufficient backup retention period is applied to RDS MySQL Instances|
|93		|RDS Instance	|SQLIAMAuthEnabled	|Ensure IAM Database Authentication feature is enabled for RDS PostgreSQL Instances|
|94		|RDS Instance	|MySQLIAMAuthEnabled	|Ensure IAM Database Authentication feature is enabled for RDS MySQL Instances|
|95		|RDS Instance	|MySQLEnableFIPS	|Ensure to enable FIPS standards on the server side for RDS MySQL Instance|
|96		|RDS Instance	|MySQLBlockEncryption	|Ensure that latest block encryption algorithms is used for RDS MySQL Instance|
|97		|RDS Snapshot	|RDSSnapshotNoPublicAccess	|Ensure that Amazon RDS database snapshots are not accessible to all AWS accounts|
|98		|Neptune Cluster	|NeptuneBackupRetention 	|Ensure AWS Neptune clusters have a sufficient backup retention period set for compliance purposes|
|99		|Neptune Cluster	|NeptuneIAMDbAuthEnabled	|Ensure IAM Database Authentication feature is enabled for Amazon Neptune clusters|
|100		|Neptune Instance	|NeptuneAutoMinorVersionUpgrade 	|Ensure Amazon Neptune instances have Auto Minor Version Upgrade feature enabled|
|101		|EC2 Instance	|EC2MonitoringState 	|Ensure that detailed monitoring is enabled for the AWS EC2 instances that you need to monitor closely|
|102		|EC2 Instance	|EC2TerminationProtection	|Ensure Termination Protection feature is enabled for EC2 instances that are not part of ASGs|
|103		|ASG	|ASGCooldown	|Ensure Amazon Auto Scaling Groups are utilizing cooldown periods|
|104	|DynamoDB	|DynamoDbContinuousBackup	|Ensure Amazon DynamoDB tables have continuous backups enabled|
|105	|SQS	|SQSSSEEnabled	|Ensure that Server-Side Encryption is enabled for Amazon SQS queues|
|106	|CloudFormation 	|StackTermination	|Ensure that Termination Protection feature is enabled for AWS CloudFormation stacks|
|107	|CloudTrail 	|CTIsLogging	|Ensure that CloudTrail trail have logging enabled|
|108	|Kinesis	|KinesisSSE	|Ensure Amazon Kinesis streams enforce Server-Side Encryption (SSE)|

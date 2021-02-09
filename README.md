# DataDog Log Detector
A containerized detector for identifying and alerting on malicious activity found in csv-formatted log events. Created by Tommy McCormick (mccormickt9@gmail.com).

## Usage

### Docker 
Build the container:
```
$ docker build -t tmccormick/detector .
```

Run with default log file provided, `dd_ad_takehome.csv`:
```
$ docker run tmccormick/detector
```

Run with your own logfile, `logfile.csv` for example:
```
$ docker run -v /tmp/logfile.csv:/logfile.csv tmccormick/detector -f /logfile.csv
```

### Build from Source
```
$ go mod download
$ go build -o detector
$ ./detector -f dd_ad_takehome.csv
```


## Alert Types

### Metadata Service Read
* Triggers on log activity indicating the user read from the cloud metadata service such as those present in EC2 or ECS.
* Alert-sepcific Information: 
    - Service endpoint IP
    - Service endpoint path
    - Mitre TTP mapping of the activity
* Response: 
    - Identify any automation workflows or tasks recently executed on the system.
    - Identify IAM privileges attached to the pricipal associated with the system.
    - Review CloudTrail or similar control plane logs for activity of the pricipal.
    - Suspend or revoke permissions if activity is unaccounted for, and ensure no exfiltration events or that any persistence exists in the form of additional users or infrastructure.

### Web Session Cookie Export
* Triggers on log activity showing an attempt to export web session cookies.
* Alert-specific information
    - Source hostname or IP of the session cookie
    - Destination filepath of the exported cookie
    - Mitre TTP mapping of the activity
* Response: 
    - Investigate the intended use of the application that the cookie was exported from.
    - Analyze the logs for further indication of the user account associated with the session cookie. 
    - Review application events for this user around the time of the alert, ensure no exfiltration activity or persistence in the form of the creation of additional users has taken place.
    - Rotate the credentials of the account or disable it once scope is identified.

### Sensitive File Read
* Triggers on log activity showing an attempt to read sensitive files such as `/etc/passwd` or `/etc/shadow`.
* Alert-sepcific Information: 
    - File path of the file read
    - Mitre TTP mapping of the activity
* Response: 
    - Identify any automation workflows or tasks recently executed on the system.
    - Review login events from privileged users or services created on the system.
    - Rotate the credentials of the all accounts on the system or disable them once scope is identified.

### Suspicious Internet Download
* Triggers on log activity showing an attempt to download a suspicious file from a remote location such as Exploit-DB or GitHub.
* Alert-specific information
    - Name of the file downloaded
    - URL of the remote file
    - Mitre TTP mapping of the activity
* Response: 
    - Review the URL of the downloaded file and if hosted on widely-known websites (github, gitlab, exploit-db), view the page and determine the use of the application or script.
    - Gather a sample of the file and query its hash against threat intelligence providers.
    - Detonate the file in a restricted sandbox analysis only environment if needed.
    - Review AV logs for triggers and update signatures if needed.
    - Analyze the system for existing vulnerabilities or misconfigurations for pivilege escalation or persistence potential.


## Enhancements with Additional Data
* The following external information could be useful in enriching these alerts and reducing false positives:
    - File hashes of downloaded files
    - VirusTotal or other threat intelligence scoring of external URLs/IPs as well as file hashes
    - Cloud account information such as EC2 instance profile or ECS task role policy attachments
    - Historical data of known true positives to baseline against
    - Institutional knowledge of administrative tasks and tooling or automation workflows


## Source Code Details
### Reference
* `types.go` - Data structures and interfaces used in the pipeline.
    - `Detector`: Defines an instance of the detector, holding its configuration, recent alerts (for throttling), and data and alerting channels.
    - `Data`: Holds the structure of a parsed log event.
    - `Alert`: Holds the structure of a alert.
    - `Severity`: Severity of an alert, from 0 - `Informational` to 4 - `Critical`.
    - `Indicator`: An interface defining methods that an `Indicator` must implement to define malicious activity and alert on it.
    - `IOC`: An struct used to embed a `name` and `description` into all `Indicator`s.
* `detector.go` - Contains the definition of the detection pipeline.
    - `Parse()`: Reads the lines of a log file, parses it into a standard data structure, and pushes it on to the data channel.
    - `Detect()`: Reads from the data channel for parsed events and analyzes the data against the configured signatures of malicious activity (i.e. `Indicators`). Sends alerts to a channel if the data matches an indicator.
    - `Alert()`: Reads from the alert channel and outputs the alert as JSON.
* `ioc.go` - Contains detection logic and alert details of each `Indicator`.
    - `Detect(d Data)`: Specifies the signature of the activity to discover in the log event. Returns `true` if theres a match and adds details to the `Indicator` struct to create an alert.
    - `Alert(d Data)`: Populates the alert information, may adjust severity based on contextual information here.
* `main.go` - Main entrypoint of the application. Defines command line flags and creates an instance of the detector.
* `util.go` - Helper functions used in creating detections.

### Adding Detections
Additions and improvements are welcome! The best way to add new detections to this application is the following:
1. Create a new `Indicator` struct in `types.go` with a descriptive name. Include details you wish to include in your alert as attributes, as well as an embedded `IOC` struct.
2. Implement the requred functions for your `Indicator` in `ioc.go`. Define your detection logic in `Detect`, and the severity and additional information to be included in your alert in `Alert`.
3. In the `GetIndicators` function in `ioc.go`, add a pointer to your struct containing your `Mitre` TTP mappings, your own custom fields to be included in your alert, and an embedded `IOC` struct with your alert `name` and `description`.
4. Add any useful helper functions created along the way in `util.go`.
# Cloud-Based-Social-Network
## Project summary
* Launched a scalable web service in Go to handle posts and deployed to Google Cloud (GAE flex).
* Used ElasticSearch (GCE) to provide geo-location based search functions such that users can search nearby posts within a distance (e.g. 200km).
* Utilized Google Dataflow to dump daily posts to a BigQuery table for offline analysis (keyword based spam detection).
* Used Google Cloud ML API and Tensorflow to train a face detection model and integrate with the Go service.

## Project Structure
![](https://github.com/Liang200/Even-Recommendation-System/blob/master/Jupiter%20readme%20image/SQLtable.png)
## Built With
* __Go__
* __Google Cloud Platfrom__
* __GCE__
* __GAE , Elasticsearch__
* __Google BigQuery , Goolge BigTable , Google Cloud ML API , Google Cloud Storage__

## Quick Start
### Google Cloud Platform
* ElasticSearch

`VPC network -> Firewall rules -> set Target tags : es , Source IP ranges : 0.0.0.0/0 , Protocols and ports tcp: 9200`

`Computer Engine -> VM instance -> Ubuntu 16.04 LTS`

`Open SSH and intstall Java`

`sudo apt-get install elasticsearch`

* Google Cloud Storage

`Storage -> Browser -> CREATE BUCKET`

`GET Json key https://cloud.google.com/storage/docs/reference/libraries#client-libraries-install-go`

* GAE

`App Engine -> Versions`

`$gcloud init`

`$gcloud app deploy`



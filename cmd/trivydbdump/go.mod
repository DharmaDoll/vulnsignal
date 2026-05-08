module trivydbdump

go 1.24

require go.etcd.io/bbolt v1.4.3

require golang.org/x/sys v0.12.0 // indirect

replace go.etcd.io/bbolt => ./third_party/go.etcd.io/bbolt

replace golang.org/x/sys => ./third_party/golang.org/x/sys

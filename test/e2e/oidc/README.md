## OIDC Test Scenarios

The purpose of these tests is to verify the OIDC functionality of the kube-rbac-proxy. When configured with OIDC
enabled, the kube-rbac-proxy validates a token received in the Authorization header and uses it to authenticate and
authorize incoming requests. Valid requests are passed to the upstream server while failed requests are rejected. To
test these scenarios a mock server (i.e., wiremock) is used in place of a real OIDC issuer (i.e., authorization server)
since the authorization server is not the subject of these tests. It is more convenient to control the test conditions
using a mock server than it would be if using an actual authorization server.

### Test Topology

                                                 ┌───────────────┐                                                     
                                                 │               │                                                     
                                                 │ OAuth Server  │                                                     
                                                 │ (mock server) │                                                     
                                                 │               │                                                     
                                                 └────────-──────┘                                                     
                                                         ▲                                                             
                                                         │                                                             
                                                         │                                                             
                                                         │                                                             
                                                         │                                                             
            ┌──────────────┐                    ┌────────-─────────┐                   ┌────────────────────────┐      
            │              │                    │                  │                   │                        │      
            │    client    ┼───────────────────►|  kube-rbac-proxy |──────────────────►| prometheus-example-app │      
            │              │                    │                  │                   │                        │      
            └──────────────┘                    └──────────────────┘                   └────────────────────────┘      

### Test Use Cases

1. Using a valid token
2. Using an expired token
3. Using a token signed by an unknown signer
4. Using a token for an unknown user
5. Using a token matching a group binding
6. Using a token for an audience not matching the configured client-id
                                                                                                                       
                                                                                                                       
                                                                                                                       
                                                                                                                       
                                                                                                                       

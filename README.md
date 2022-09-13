# PSI with go

Private Set Intersection (PSI) protocol based on Elliptic Curve Diffie-Hellman explained [here](https://arxiv.org/pdf/2011.09350.pdf).  
The implementation of the authors can be found [here](https://github.com/OpenMined/PSI).  

The package only provides the usage of the cryptography. The elliptic curve cryptography is handled by the [CIRCL](https://github.com/cloudflare/circl) package.  

The _test file shows how PSI would work.
module github.com/intuitivelabs/sipcallmon

go 1.15

require (
	github.com/google/gopacket v1.1.18
	github.com/intuitivelabs/bytescase v1.0.2-0.20210217091653-e8baf7a3651d
	github.com/intuitivelabs/calltr v1.0.2-0.20210405163501-b24a6bed434b
	github.com/intuitivelabs/counters v0.1.2-0.20210707135030-94c624574f9c
	github.com/intuitivelabs/sipsp v1.0.3-0.20210705201220-efbf7165d0a8
	github.com/intuitivelabs/slog v0.0.2-0.20210321224300-46645dc5b0ce
	github.com/intuitivelabs/timestamp v0.0.3-0.20210323191703-3e5e3588bfd0
	golang.org/x/sys v0.0.0-20191026070338-33540a1f6037 // indirect
)

replace github.com/intuitivelabs/counters => /home/andrei/devel/go/src/andrei/counters

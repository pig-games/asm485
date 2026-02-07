# Reference Output

These are known-good outputs from assembling files in the examples directory. When the assembler is modified, the examples should be assembled and their list/hex/map files compared to these files.

Examples that are expected to fail use `.err` reference files containing the exact expected error text.

If differences are found due to a bug fix or syntax change, new versions of these reference files should be generated and checked in.

Note that a change in the assembler version will cause a difference in the first line of the list file. There is no need to check in a new version of the reference files if this is the only difference.

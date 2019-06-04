//Committer
auto dlog = make_shared<OpenSSLDlogECF2m>("K-233");
CmtPedersenCommitter committer(ch, dlog, get_seed_prg());

vector<byte< msg(10,0);
auto val = committer.generateCommitValue(msg);

committer.commit(val, 2);

committer.decomit(2);

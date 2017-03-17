create table cve
(
  cveid varchar(16) NOT NULL,
  cveentitle varchar(4096) DEFAULT NULL,
  cvecntitle varchar(4096) DEFAULT NULL,
  des text DEFAULT NULL,
  cnnvdid varchar(32) DEFAULT NULL,
  cvssScore varchar(16) DEFAULT NULL,
  secrecyEff varchar(16) DEFAULT NULL,
  completeEff varchar(16) DEFAULT NULL,
  enableEff varchar(16) DEFAULT NULL,
  attackComplex varchar(16) DEFAULT NULL,
  attackVec varchar(16) DEFAULT NULL,
  identityCred varchar(16) DEFAULT NULL,
  CPE text DEFAULT NULL,
  CWE varchar(32) DEFAULT NULL,
  vulType varchar(32) DEFAULT NULL,
  releaseDate varchar(32) DEFAULT NULL,
  updateDate varchar(32) DEFAULT NULL,
  atkUrl varchar(16) DEFAULT NULL,
  BugtraqID integer DEFAULT NULL,
  reportAndHotfix text DEFAULT NULL,
  PRIMARY KEY (cveid)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
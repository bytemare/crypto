package ed25519

type Test struct {
	L           string `json:"L"`
	Z           string `json:"Z"`
	Ciphersuite string `json:"ciphersuite"`
	Curve       string `json:"curve"`
	Dst         string `json:"dst"`
	Expand      string `json:"expand"`
	Field       struct {
		M string `json:"m"`
		P string `json:"p"`
	} `json:"field"`
	Hash string `json:"hash"`
	K    string `json:"k"`
	Map  struct {
		Name string `json:"name"`
	} `json:"map"`
	RandomOracle bool `json:"randomOracle"`
	Vectors      []struct {
		P struct {
			X string `json:"x"`
			Y string `json:"y"`
		} `json:"P"`
		Q0 struct {
			X string `json:"x"`
			Y string `json:"y"`
		} `json:"Q0"`
		Q1 struct {
			X string `json:"x"`
			Y string `json:"y"`
		} `json:"Q1"`
		Msg string   `json:"msg"`
		U   []string `json:"u"`
	} `json:"vectors"`
}

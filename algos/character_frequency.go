package algos

import "math"

var CharacterFrequency = createFrequencyArray()

func createFrequencyArray() []float64 {
	result := make([]float64, math.MaxUint8+1)

	for i := range result {
		result[i] = characterFrequencyMap[byte(i)]
	}

	return result
}

var characterFrequencyMap = map[byte]float64{
	'\t': 0.000057,
	'\n': 0.020827,
	23:   0.000000,
	' ':  0.171662,
	'!':  0.000072,
	'"':  0.002442,
	'#':  0.000179,
	'$':  0.000561,
	'%':  0.000160,
	'&':  0.000226,
	'\'': 0.002447,
	'(':  0.002178,
	')':  0.002233,
	'*':  0.000628,
	'+':  0.000215,
	',':  0.007384,
	'-':  0.013734,
	'.':  0.015124,
	'/':  0.001549,
	'0':  0.005516,
	'1':  0.004594,
	'2':  0.003322,
	'3':  0.001847,
	'4':  0.001348,
	'5':  0.001663,
	'6':  0.001153,
	'7':  0.001030,
	'8':  0.001054,
	'9':  0.001024,
	':':  0.004354,
	';':  0.001214,
	'<':  0.001225,
	'=':  0.000227,
	'>':  0.001242,
	'?':  0.001474,
	'@':  0.000073,
	'A':  0.003132,
	'B':  0.002163,
	'C':  0.003906,
	'D':  0.003151,
	'E':  0.002673,
	'F':  0.001416,
	'G':  0.001876,
	'H':  0.002321,
	'I':  0.003211,
	'J':  0.001726,
	'K':  0.000687,
	'L':  0.001884,
	'M':  0.003529,
	'N':  0.002085,
	'O':  0.001842,
	'P':  0.002614,
	'Q':  0.000316,
	'R':  0.002519,
	'S':  0.004003,
	'T':  0.003322,
	'U':  0.000814,
	'V':  0.000892,
	'W':  0.002527,
	'X':  0.000343,
	'Y':  0.000304,
	'Z':  0.000076,
	'[':  0.000086,
	'\\': 0.000016,
	']':  0.000088,
	'^':  0.000003,
	'_':  0.001159,
	'`':  0.000009,
	'a':  0.051880,
	'b':  0.010195,
	'c':  0.021129,
	'd':  0.025071,
	'e':  0.085771,
	'f':  0.013725,
	'g':  0.015597,
	'h':  0.027444,
	'i':  0.049019,
	'j':  0.000867,
	'k':  0.006753,
	'l':  0.031750,
	'm':  0.016437,
	'n':  0.049701,
	'o':  0.057701,
	'p':  0.015482,
	'q':  0.000747,
	'r':  0.042586,
	's':  0.043686,
	't':  0.063700,
	'u':  0.020999,
	'v':  0.008462,
	'w':  0.013034,
	'x':  0.001950,
	'y':  0.011330,
	'z':  0.000596,
	'{':  0.000026,
	'|':  0.000007,
	'}':  0.000026,
	'~':  0.000003,
	131:  0.000000,
	149:  0.006410,
	'·':  0.000010,
	'ß':  0.000000,
	'â':  0.000000,
	'å':  0.000000,
	'æ':  0.000000,
	'í':  0.000000,
}

// http://www.fitaly.com/board/domper3/posts/136.html

import strutils

let scrambled = @[
  "}.ti no naeL .ti htiw gubeD .ti tpmorP .taemmate repoleved ruoy si IA{syap taht esarhP ehT",
  ".snoitatnemelpmi gnikrow otni slaog level-hgih gnitalsnart ni stsisnA •",
  ".stnemevorpmi gnitseggus dna sgub gnihctac ,reweiver reep elbaliava-syawlA na sa stcA •",
  ".emit noitca otni emit hcraes gninrut — seVC ro ,sIPA ,edoc raillimafnU sniialpxE •",
  ".selpmaxe gnikrow gnitareneg yb retsaf tset dna epytotorp uoy spleH •",
  ".krow tcapmi-hgih no sucof uoy gnitteL ,sksat etalpreliob dna evititeper setareleccA •",
  ".ksa ot woh gninwok s’ti ,gnihtyreve gninwok t’nsi lliks laer ehT •",
  ".snoitseuq doog htiw deriap nehw tseb era sloot lufrewop •",
  ":noisulcnoC"
]

proc decode(s: string): string =
  return s.reverse()

for s in scrambled:
  echo decode(s)

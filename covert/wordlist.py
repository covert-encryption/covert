# A custom list of 1024 common 2-7 letter words, with unique 3-prefixes and no prefix words, entropy 2.2b/letter 10b/word
words: list = """
abbey about abroad abuse access act adam added adept adopt affect again age agreed aid air aisle akin alan albert alcott
alder alert algae alive all along alpha alter amazed amber amer amino among anal anchor andrew angle animal annual anon
answer anti appear arab arbor arch are argued arise army arnold array art ascent ash asia aspect assume asthma atomic
attack audit august aura author avant avenue aviv avoid away baby back bad bag bailey baker ball bank bar based battle
bauer bay bear become been began behind being below ben berlin best better bhakti bias bible bid big bill binary bio
birth bishop bit black blend blind blood blue board bob body bog bold bone book born boston both bound bowl boy brain
break bring brown brush buck budget buffer bug bulk bump bunch bureau bus but cable cache cad cairo called came can cap
care case catch cause cave cedar cells center cereal change check child choice church cinema circle city class clear
client close club coast code coins cold come con cool copy core cost cotton could cover cow craft create crisis cross
crude cuba cues cult curve custom dac daily dallas damage danger dark data david dawn day death debt decide deep define
deity del demand denied depth derive design detail device dialog dick die dig dilute dim dinner diode direct disk divine
doctor dodge dog dollar domain done door dorsal dose dot doubt down drawn dream drive drop drug dublin duct dull dumb
duncan duplex during dust early east eat eco editor effect ego eiffel elaine eleven elite ellen embryo emily empire end
engine ensure entire envy equal era erect eric error escape esp essay estate ethnic evans even evil exact except exempt
exist expect extent fabric fact faith fall family fan far fast father fault fear feel fein felt female fence ferry fes
fetal fichte fide field fifty file find first fish fit fixed flat flesh flight flow fluid foil follow fond food for
found france free friend from fuel full funds fur fusion gain galaxy game gang garden gas gate gauge gay geese gel
gender george german ghana gibson gill ginger girl given glass glenn glide global glue goal god goes gold gone good
gordon got gould gown grant great grid group grudge guard guide gulf gun guru gustav gut habits hack had hague hair half
hammer hand hard has hat haul have hawaii hay hazard head hebrew hector hedge heels height help hem henry her hess hill
hindu hip hired hoarse hobbes hold home honor hook hope horse host hot house how hub huge hull human hung hurt hush hut
ica idea ill image impact income indeed infant inland inner inside into island italy jack jagged jail james jan jar jed
jenny jersey jesus jet jewish jin joint jolly jones jordan joseph judge july jump june jury just kahn kali kama kansas
kaplan karl kassel kate keep keith kelly kent kernel khan kids killed kind kirk kiss kit klaus knew know kolb kong korea
kosovo kramer kris kroll kung kurt labor lack lady lag laid lake lamp land lap large last later laugh lava law lay least
lectin led lee legal leiden lemon length leo leper less let level liable libya lick lid lies life light like lily limit
line lips list little living load lobby local lodge logic lome long look lord lost lot louis love low luck lug lumber
lunch lure lust luther lynn mac made magic mahler main make male mama many map market mass matter maud max may mccoy
means media meet melt member men merely mess method mice middle miles mimic mind mirror miss mit mobile model mohr moist
mol money moon more most mother mouth move mowing much multi munich murder must mutual myriad obey oculus oder off oil
oliver open opium option oral order organ origin orthop out oxygen pace pad page pain palace panel paper part past path
paul paw pay peace peck pedro peer pelvic pen pepper per pest peter phase philip phone piano pick piece pilot pink pipe
pistol pitch place please plot plus poetry point policy pomp pond poor pope port post pot pounds prayer press price
proper puerto pulled punch pupils pure pushed put qatar qed quasi queen quest quite quoted rabbit race radio raft rage
raised rake ram range rapid rash rather raven ray razor real rebel recent red reed reform region reign relief remain
rent report result return review rhesus ribs rich ride rifle right rim ring ripe risk river road robert rock rod roger
role roman ronald room rose roth round row rubber rude rumors run russia sabha sacred sad safety sage said sake sales
same santa sarah sas sat sauce save saw say scale school scope screen scuba sea second sed see segal seized self semi
sense series set seven sewing sexual shall she ship should shri shut sick side sierra sign silver simply since sir site
sketch skills slave sleep slight slowly sludge small smell smith smooth snake sneak sniff snow soap sodium soft solid
some son sort south sown space speech spirit split spoke spring spun square state step still story strong study style
sub such sudden suit sultan summer sun supply sure susan suture swamp sweet switch sword syntax syria table tackle tail
take talk tamil tank tape target task tate taught tax team tech teeth tell temple ten terms test text that the this
those three thus tibet ticket tied tight till time tiny tip tired title toby today told tom tone too top torn tossed
total touch toward trade tree tried troops true tube tulsa tumor tunnel turn tutor twenty twice type tyrant uncle under
united unrest unseen until urine value van vary vast vein velvet venice very vessel veto via vice video view villa vine
virtue visit vital vivo voice volume vote wade wage wait wall want war was water wave wealth week weight well went were
west what when which who wicked wide wig will window wire wish with wolf wood work wreck write xander xbox xerox xi xray
yang years yellow yes yin york you zane zara zen zippo zorro zulu
""".split()
assert len(words) == 1024  # Exactly 10 bits of entropy per word

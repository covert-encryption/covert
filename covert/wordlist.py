# A custom list of 1024 common 3-6 letter words, with unique 3-prefixes and no prefix words, entropy 2.1b/letter 10b/word
words: list = """
able about absent abuse access acid across act adapt add adjust admit adult advice affair afraid again age agree ahead
aim air aisle alarm album alert alien all almost alone alpha also alter always amazed among amused anchor angle animal
ankle annual answer any apart appear april arch are argue army around array art ascent ash ask aspect assume asthma atom
attack audit august aunt author avoid away awful axis baby back bad bag ball bamboo bank bar base battle beach become
beef before begin behind below bench best better beyond bid bike bind bio birth bitter black bleak blind blood blue
board body boil bomb bone book border boss bottom bounce bowl box boy brain bread bring brown brush bubble buck budget
build bulk bundle burden bus but buyer buzz cable cache cage cake call came can car case catch cause cave celery cement
census cereal change check child choice chunk cigar circle city civil class clean client close club coast code coffee
coil cold come cool copy core cost cotton couch cover coyote craft cream crime cross cruel cry cube cue cult cup curve
custom cute cycle dad damage danger daring dash dawn day deal debate decide deer define degree deity delay demand denial
depth derive design detail device dial dice die differ dim dinner direct dish divert dizzy doctor dog dollar domain
donate door dose double dove draft dream drive drop drum dry duck dumb dune during dust dutch dwarf eager early east
echo eco edge edit effort egg eight either elbow elder elite else embark emerge emily employ enable end enemy engine
enjoy enlist enough enrich ensure entire envy equal era erode error erupt escape essay estate ethics evil evoke exact
excess exist exotic expect extent eye fabric face fade faith fall family fan far father fault feel female fence fetch
fever few fiber field figure file find first fish fit fix flat flesh flight float fluid fly foam focus fog foil follow
food force fossil found fox frame fresh friend frog fruit fuel fun fury future gadget gain galaxy game gap garden gas
gate gauge gaze genius ghost giant gift giggle ginger girl give glass glide globe glue goal god gold good gospel govern
gown grant great grid group grunt guard guess guide gulf gun gym habit hair half hammer hand happy hard hat have hawk
hay hazard head hedge height help hen hero hidden high hill hint hip hire hobby hockey hold home honey hood hope horse
host hotel hour hover how hub huge human hungry hurt hybrid ice icon idea idle ignore ill image immune impact income
index infant inhale inject inmate inner input inside into invest iron island issue italy item ivory jacket jaguar james
jar jazz jeans jelly jewel job joint joke joy judge juice july jump june just kansas kate keep kernel key kick kid kind
kiss kit kiwi knee knife know labor lady lag lake lamp laptop large later laugh lava law layer lazy leader left legal
lemon length lesson letter level liar libya lid life light like limit line lion liquid list little live lizard load
local logic long loop lost loud love low loyal lucky lumber lunch lust luxury lyrics mad magic main major make male
mammal man map market mass matter maze mccoy meadow media meet melt member men mercy mesh method middle milk mimic mind
mirror miss mix mobile model mom monkey moon more mother mouse move much muffin mule must mutual myself myth naive name
napkin narrow nasty nation near neck need nephew nerve nest net never news next nice night noble noise noodle normal
nose note novel now number nurse nut oak obey object oblige obtain occur ocean odor off often oil okay old olive omit
once one onion online open opium oppose option orange orbit order organ orient orphan other outer oval oven own oxygen
oyster ozone pact paddle page pair palace panel paper parade past path pause pave paw pay peace pen people pepper permit
pet philip phone phrase piano pick piece pig pilot pink pipe pistol pitch pizza place please pluck poem point polar pond
pool post pot pound powder praise prefer price profit public pull punch pupil purity push put puzzle qatar quasi queen
quite quoted rabbit race radio rail rally ramp range rapid rare rather raven raw razor real rebel recall red reform
region reject relief remain rent reopen report result return review reward rhythm rib rich ride rifle right ring riot
ripple risk ritual river road robot rocket room rose rotate round row royal rubber rude rug rule run rural sad safe sage
sail salad same santa sauce save say scale scene school scope screen scuba sea second seed self semi sense series settle
seven shadow she ship shock shrimp shy sick side siege sign silver simple since siren sister six size skate sketch ski
skull slab sleep slight slogan slush small smile smooth snake sniff snow soap soccer soda soft solid son soon sort south
space speak sphere spirit split spoil spring spy square state step still story strong stuff style submit such sudden
suffer sugar suit summer sun supply sure swamp sweet switch sword symbol syntax syria system table tackle tag tail talk
tank tape target task tattoo taxi team tell ten term test text that theme this three thumb tibet ticket tide tight tilt
time tiny tip tired tissue title toast today toe toilet token tomato tone tool top torch toss total toward toy trade
tree trial trophy true try tube tumble tunnel turn twenty twice two type ugly unable uncle under unfair unique unlock
until unveil update uphold upon upper upset urban urge usage use usual vacuum vague valid van vapor vast vault vein
velvet vendor very vessel viable video view villa violin virus visit vital vivid vocal voice volume vote voyage wage
wait wall want war wash water wave way wealth web weird were west wet what when whip wide wife will window wire wish
wolf woman wonder wood work wrap wreck write wrong xander xbox xerox xray yang yard year yellow yes yin york you zane
zara zebra zen zero zippo zone zoo zorro zulu
""".split()
assert len(words) == 1024  # Exactly 10 bits of entropy per word

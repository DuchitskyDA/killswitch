package ui

import (
	"errors"
	"fmt"
	"net/netip"
	"path"
	"slices"
	"strings"

	"github.com/DuchitskyDA/killswitch/internal/policy"
)

// settings — черновик конфига. Файл пишет только «Применить и сохранить» (Actions.Save).
type settings struct {
	m        *menu
	cfg      policy.Config
	profiles []Profile
	dirty    bool
}

func (m *menu) settingsScreen() {
	cfg, err := m.act.LoadConfig()
	if err != nil {
		m.printf("config.toml не читается: %v\nнастройки начнутся с пустых; «Применить» перезапишет файл\n", err)
		cfg = policy.Config{}
	}
	s := &settings{m: m, cfg: cfg, profiles: m.act.Profiles()}
	for !m.done {
		if m.choose(s.title(), s.items(), "Назад") {
			continue
		}
		if !s.dirty || m.done || m.confirm("Изменения не сохранены.", "Выйти без сохранения", "Остаться") {
			return
		}
	}
}

func (s *settings) title() string {
	if s.dirty {
		return "Настройки (есть несохранённые правки)"
	}
	return "Настройки"
}

func (s *settings) items() []item {
	items := []item{
		{"Клиент туннеля: " + s.profileName() + "  [найти автоматически]", s.clientScreen},
		{"Локальная сеть: " + onOff(s.lan(), "разрешена", "закрыта"), s.toggleLAN},
		{"DNS: " + s.dnsText(), s.dnsScreen},
		{"Строгий режим: " + s.strictText(), s.strictScreen},
		{s.trustTitle() + ": " + s.trustSummary(), s.trustScreen},
	}
	if s.m.caps.Repair {
		items = append(items, item{"Закрыты в починке: " + summary(s.repairList().items, "никто"), s.repairScreen})
	}
	items = append(items,
		item{"Адреса для проверки утечек: " + summary(strList(s.cfg.Check.Targets).items, "не заданы"), s.targetsScreen},
		item{"Применить и сохранить", s.apply},
	)
	return items
}

func (s *settings) changed(c policy.Config) {
	s.cfg, s.dirty = c, true
}

func (s *settings) apply() {
	data, err := policy.Encode(s.cfg)
	if err != nil {
		s.m.report(err)
		return
	}
	saved, err := s.m.act.Save(data)
	if saved != "" {
		s.m.printf("%s\n", saved)
		s.dirty = false
	}
	if err != nil {
		s.m.printf("%v\n", err)
	}
}

func onOff(v bool, yes, no string) string {
	if v {
		return yes
	}
	return no
}

// --- клиент туннеля ---

func (s *settings) profileName() string {
	if s.cfg.Profile == "" {
		return "не выбран"
	}
	return s.cfg.Profile
}

func (s *settings) layer() policy.Layer { return s.layerOf(s.cfg.Profile) }

func (s *settings) layerOf(name string) policy.Layer {
	for _, p := range s.profiles {
		if p.Name == name {
			return p.Layer
		}
	}
	return policy.Layer{}
}

func (s *settings) clientScreen() {
	for !s.m.done {
		ifs := s.interfaceList()
		items := []item{
			{"Найти автоматически", s.detect},
			{"Выбрать из списка", s.pickProfile},
			{"Адаптеры туннеля: " + summary(ifs.items, "не заданы") + inheritNote(s.cfg.Profile != "", ifs.set), s.interfacesScreen},
		}
		if !s.m.choose("Клиент туннеля: "+s.profileName(), items, "Назад") {
			return
		}
	}
}

func (s *settings) detect() {
	var found []string
	for _, name := range s.m.act.Detect() {
		if slices.ContainsFunc(s.profiles, func(p Profile) bool { return p.Name == name }) && !slices.Contains(found, name) {
			found = append(found, name)
		}
	}
	switch len(found) {
	case 0:
		s.m.printf("установленные клиенты не найдены — выберите из списка\n")
	case 1:
		s.m.printf("найден клиент: %s\n", found[0])
		s.setProfile(found[0])
	default:
		var items []item
		for _, name := range found {
			items = append(items, item{name, func() { s.setProfile(name) }})
		}
		s.m.choose("Найдено несколько клиентов:", items, "Отмена")
	}
}

func (s *settings) pickProfile() {
	var items []item
	for _, p := range s.profiles {
		items = append(items, item{p.Name + " — " + p.Description, func() { s.setProfile(p.Name) }})
	}
	items = append(items, item{"Без профиля (адаптеры и доверенные — вручную)", func() { s.setProfile("") }})
	s.m.choose("Клиент туннеля:", items, "Отмена")
}

// setProfile меняет клиента. Списки конфига, равные списку прежнего профиля, убираются — их даст новый;
// свои списки — по выбору пользователя. Без профиля действующие списки становятся своими.
func (s *settings) setProfile(name string) {
	if name == s.cfg.Profile {
		return
	}
	c, old := s.cfg, s.layer()
	if name == "" {
		c.Tunnel.Interfaces = putStrList(listValue[string]{items: s.interfaceList().items, set: true})
		trust, _ := s.trustList()
		c.SetTrust(trust.items)
		c.Repair.Programs = putStrList(listValue[string]{items: s.repairList().items, set: true})
		c.Profile = ""
		s.changed(c)
		return
	}
	if v := strList(c.Tunnel.Interfaces); v.set && !s.keepOwn("Адаптеры туннеля", name, slices.Equal(v.items, old.Interfaces)) {
		c.Tunnel.Interfaces = nil
	}
	if t, set := c.TrustEntries(); set && !s.keepOwn("Доверенные", name, slices.Equal(t, old.Trust)) {
		c.SetTrust(nil)
	}
	if v := strList(c.Repair.Programs); v.set && !s.keepOwn("Закрытые в починке", name, slices.Equal(v.items, old.RepairPrograms)) {
		c.Repair.Programs = nil
	}
	c.Profile = name
	s.changed(c)
}

// keepOwn: оставить ли свой список при смене клиента. Список, равный прежнему профилю, не свой.
func (s *settings) keepOwn(what, name string, sameAsOld bool) bool {
	if sameAsOld {
		return false
	}
	return s.m.confirm(what+" заданы вручную.", "Оставить свои", "Взять из профиля "+name)
}

func (s *settings) interfaceList() listValue[string] {
	v := strList(s.cfg.Tunnel.Interfaces)
	if !v.set {
		v.items = s.layer().Interfaces
	}
	return v
}

func (s *settings) interfacesScreen() {
	v, changed := editList(s.m, listSpec[string]{
		title:   "Адаптеры туннеля (имя, alias или описание; можно * и ?)",
		profile: s.layer().Interfaces,
		inherit: s.cfg.Profile != "",
		format:  identity,
		add: func() (string, bool) {
			return s.m.prompt("Шаблон адаптера", func(p string) error {
				_, err := path.Match(p, "")
				return err
			})
		},
	}, strList(s.cfg.Tunnel.Interfaces))
	if changed {
		c := s.cfg
		c.Tunnel.Interfaces = putStrList(v)
		s.changed(c)
	}
}

// --- локальная сеть ---

func (s *settings) lan() bool { return s.cfg.LAN == nil || *s.cfg.LAN }

func (s *settings) toggleLAN() {
	c, v := s.cfg, !s.lan()
	c.LAN = &v
	s.changed(c)
}

// --- DNS ---

func (s *settings) dnsMode() policy.DNSMode {
	if s.cfg.DNS.Mode == nil {
		return policy.DNSOpen
	}
	return policy.DNSMode(*s.cfg.DNS.Mode)
}

func (s *settings) dnsText() string {
	switch s.dnsMode() {
	case policy.DNSOpen:
		return "open — к локальной сети и резолверам DHCP"
	case policy.DNSTunnelUp:
		h := "адрес проверки не задан"
		if s.cfg.DNS.Health != nil {
			h = "проверка " + *s.cfg.DNS.Health
		}
		return "tunnel-up — закрыт, пока туннель жив (" + h + ")"
	case policy.DNSResolvers:
		return "только свои резолверы: " + summary(strList(s.cfg.DNS.Resolvers).items, "не заданы")
	}
	return string(s.dnsMode())
}

func (s *settings) dnsScreen() {
	s.m.choose("DNS мимо туннеля (порт 53). Сейчас: "+s.dnsText(), []item{
		{"open — к локальной сети и резолверам DHCP", func() { s.setDNS(policy.DNSOpen, nil) }},
		{"tunnel-up — закрыт, пока туннель жив (нужен адрес проверки)", s.tunnelUp},
		{"Только свои резолверы", s.resolvers},
	}, "Назад")
}

func (s *settings) setDNS(mode policy.DNSMode, resolvers *[]string) {
	c, m := s.cfg, string(mode)
	c.DNS.Mode, c.DNS.Resolvers = &m, resolvers
	s.changed(c)
}

func (s *settings) tunnelUp() {
	if s.m.caps.OS == "linux" {
		// sing-box auto_redirect перехватывает трафик nft, а маршрут к адресу проверки идёт через физику: здоровье
		// туннеля не поднимается (ограничение описано в README).
		s.m.printf("с sing-box auto_redirect режим tunnel-up не поднимается — используйте open или свои резолверы\n")
	}
	label := "Адрес проверки туннеля http://<ip>:<порт>/<путь>"
	if h := s.cfg.DNS.Health; h != nil {
		label += " (сейчас " + *h + ", пусто — оставить) "
	} else {
		label += " (пусто — отмена) "
	}
	in := s.m.ask(label)
	if in == "" {
		if s.cfg.DNS.Health != nil {
			s.setDNS(policy.DNSTunnelUp, nil)
		}
		return
	}
	if _, err := policy.ParseHealthURL(in); err != nil {
		s.m.printf("не принято: %v\n", err)
		return
	}
	s.setDNS(policy.DNSTunnelUp, nil)
	s.cfg.DNS.Health = &in
}

func (s *settings) resolvers() {
	v, changed := editList(s.m, listSpec[string]{
		title:  "Свои резолверы: только к ним порт 53 мимо туннеля (адрес или подсеть)",
		format: identity,
		add: func() (string, bool) {
			return s.m.prompt("Адрес или подсеть резолвера", checkResolver)
		},
	}, strList(s.cfg.DNS.Resolvers))
	switch {
	case !changed && (s.dnsMode() == policy.DNSResolvers || len(v.items) == 0):
		return // список не тронут — режим прежний
	case len(v.items) > 0:
		s.setDNS(policy.DNSResolvers, putStrList(v))
	default:
		s.m.printf("список пуст — DNS: open\n")
		s.setDNS(policy.DNSOpen, nil)
	}
}

func checkResolver(r string) error {
	if strings.Contains(r, "/") {
		_, err := netip.ParsePrefix(r)
		return err
	}
	_, err := netip.ParseAddr(r)
	return err
}

// --- строгий режим и серверы туннеля ---

func (s *settings) strict() bool {
	return s.cfg.TrustMode != nil && policy.TrustMode(*s.cfg.TrustMode) == policy.TrustStrict
}

func (s *settings) strictText() string {
	return fmt.Sprintf("%s, серверов туннеля: %d", onOff(s.strict(), "вкл", "выкл"), len(strList(s.cfg.Tunnel.Endpoints).items))
}

func (s *settings) strictScreen() {
	for !s.m.done {
		items := []item{
			{"Строгий режим: " + onOff(s.strict(), "вкл", "выкл") + " — переключить", s.toggleStrict},
			{"Серверы туннеля: " + summary(strList(s.cfg.Tunnel.Endpoints).items, "не заданы"), s.endpointsScreen},
		}
		if !s.m.choose("Строгий режим — доверенные ходят только к серверам туннеля", items, "Назад") {
			return
		}
	}
}

func (s *settings) toggleStrict() {
	c, mode := s.cfg, string(policy.TrustStrict)
	if s.strict() {
		mode = string(policy.TrustCompat)
	}
	c.TrustMode = &mode
	s.changed(c)
	if s.strict() && len(strList(c.Tunnel.Endpoints).items) == 0 {
		s.m.printf("добавьте хотя бы один сервер туннеля — без него настройки не сохранятся\n")
	}
}

func (s *settings) endpointsScreen() {
	v, changed := editList(s.m, listSpec[string]{
		title:  "Серверы туннеля (адрес или имя, порт, tcp|udp)",
		format: identity,
		add: func() (string, bool) {
			return s.m.prompt("Сервер host:порт/tcp или udp (IPv6 — в [скобках])", func(e string) error {
				_, err := policy.ParseEndpoint(e)
				return err
			})
		},
	}, strList(s.cfg.Tunnel.Endpoints))
	if changed {
		c := s.cfg
		c.Tunnel.Endpoints = putStrList(v)
		s.changed(c)
	}
}

// --- доверенные ---

var kindOrder = []policy.TrustKind{policy.KindProgram, policy.KindUser, policy.KindCgroup, policy.KindMark}

var kindNames = map[policy.TrustKind]string{
	policy.KindProgram: "программа", policy.KindUser: "пользователь", policy.KindCgroup: "cgroup", policy.KindMark: "метка",
}

var kindPrompts = map[policy.TrustKind]string{
	policy.KindProgram: "Путь программы (можно * и ?)",
	policy.KindUser:    "Имя пользователя",
	policy.KindCgroup:  "Путь cgroup",
	policy.KindMark:    "Метка (например 0xca6c)",
}

// kinds — виды доверия, которые умеет ОС.
func (s *settings) kinds() []policy.TrustKind {
	var out []policy.TrustKind
	for _, k := range kindOrder {
		if s.m.caps.Trust[k] {
			out = append(out, k)
		}
	}
	return out
}

func (s *settings) trustTitle() string {
	var names []string
	for _, k := range s.kinds() {
		names = append(names, kindNames[k])
	}
	return "Доверенные (" + strings.Join(names, ", ") + ")"
}

func (s *settings) trustList() (listValue[policy.Trust], bool) {
	t, set := s.cfg.TrustEntries()
	if !set {
		t = s.layer().Trust
	}
	return listValue[policy.Trust]{items: t, set: set}, set
}

func (s *settings) trustSummary() string {
	v, set := s.trustList()
	var names []string
	for _, t := range v.items {
		names = append(names, path.Base(strings.ReplaceAll(t.Value, `\`, "/")))
	}
	return summary(names, "нет") + inheritNote(s.cfg.Profile != "", set)
}

func (s *settings) trustScreen() {
	t, set := s.cfg.TrustEntries()
	v, changed := editList(s.m, listSpec[policy.Trust]{
		title:   "Доверенные — ходят мимо защиты",
		profile: s.layer().Trust,
		inherit: s.cfg.Profile != "",
		format:  s.trustText,
		add:     s.addTrust,
	}, listValue[policy.Trust]{items: t, set: set})
	if !changed {
		return
	}
	c := s.cfg
	if v.set {
		c.SetTrust(v.items)
	} else {
		c.SetTrust(nil)
	}
	s.changed(c)
}

func (s *settings) trustText(t policy.Trust) string {
	dest := "куда угодно"
	if t.Destinations == policy.DestEndpoints || (t.Destinations == "" && s.strict()) {
		dest = "только к серверам туннеля"
	}
	return kindNames[t.Kind] + " " + t.Value + " — " + dest
}

func (s *settings) addTrust() (policy.Trust, bool) {
	kinds := s.kinds()
	if len(kinds) == 0 {
		s.m.printf("на этой ОС исключения не поддерживаются\n")
		return policy.Trust{}, false
	}
	kind := kinds[0]
	if len(kinds) > 1 {
		var items []item
		picked := false
		for _, k := range kinds {
			items = append(items, item{kindNames[k], func() { kind, picked = k, true }})
		}
		if s.m.choose("Вид:", items, "Отмена"); !picked {
			return policy.Trust{}, false
		}
	}
	value, ok := s.m.prompt(kindPrompts[kind], func(string) error { return nil })
	if !ok {
		return policy.Trust{}, false
	}
	t := policy.Trust{Kind: kind, Value: value}
	if s.strict() {
		s.m.printf("в строгом режиме — только к серверам туннеля\n")
		return t, true
	}
	picked := false
	s.m.choose("Куда можно:", []item{
		{"Куда угодно (пока строгий режим выкл)", func() { picked = true }},
		{"Только к серверам туннеля", func() { t.Destinations, picked = policy.DestEndpoints, true }},
	}, "Отмена")
	return t, picked
}

// --- починка и проверка ---

func (s *settings) repairList() listValue[string] {
	v := strList(s.cfg.Repair.Programs)
	if !v.set {
		v.items = s.layer().RepairPrograms
	}
	return v
}

func (s *settings) repairScreen() {
	v, changed := editList(s.m, listSpec[string]{
		title:   "Закрыты в починке — в режиме починки только им закрыт выход",
		profile: s.layer().RepairPrograms,
		inherit: s.cfg.Profile != "",
		format:  identity,
		add: func() (string, bool) {
			return s.m.prompt("Путь программы (можно * и ?)", func(string) error { return nil })
		},
	}, strList(s.cfg.Repair.Programs))
	if changed {
		c := s.cfg
		c.Repair.Programs = putStrList(v)
		s.changed(c)
	}
}

func (s *settings) targetsScreen() {
	v, changed := editList(s.m, listSpec[string]{
		title:  "Адреса для проверки утечек (слушают HTTP 80, UDP-эхо 443, DNS 53)",
		format: identity,
		add: func() (string, bool) {
			return s.m.prompt("IP-адрес цели", func(a string) error {
				if _, err := netip.ParseAddr(a); err != nil {
					return errors.New("нужен IP-адрес")
				}
				return nil
			})
		},
	}, strList(s.cfg.Check.Targets))
	if changed {
		c := s.cfg
		c.Check.Targets = putStrList(v)
		s.changed(c)
	}
}

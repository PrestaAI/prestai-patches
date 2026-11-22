// patches.cjs: the catalog of this repository on a clean PrestaShop of one of its versions, with PrestAI Core
// (prestai-ci: run.sh with Core as the module and this folder as TESTS_DIR; PATCHES_DIR: this repository, its
// dist/files written by bin/build --dist).
// - the catalog accepted by Core: with the keys of Core and catalog.json.sig (PATCHES_SIGNED=1: the release), else with
//   a key made during the test and given to the code of verification (the CI, before the signature);
// - on the clean shop, every patch of this version « to apply » (every file the official one, the new ones absent),
//   every advisory fixed in this version « integrated »;
// - before the patches, the flaws seen: B17 (a customization file with the order reference alone), B18 (the reset
//   token computed from the time and the secure key), A1 to A5 when the version has the catch-up;
// - the patches applied by the console (--confirm=OUI, --files), each file checked against the catalog;
// - after: B8 (two orders at once, one voucher of one use: used once), B9 (a free cart asked six times at once: one
//   order), B17, B18, A1 to A5 refused; normal use (an order paid by bank wire, a free order with a voucher, the list
//   of the cart rules filtered, the notifications, the export of the customers);
// - reverted by the console: every file back to the official one, the new ones removed, B17 seen again.
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const ci = require(process.env.PRESTAI_CI_TEST);

const ROOT = process.env.PATCHES_DIR || path.resolve(__dirname, '..', '..');
const PASSWD = 'Pr3staiSecu!2026';

ci.run(async (t) => {
  const json = (text) => {
    try {
      return JSON.parse(String(text).slice(String(text).indexOf('{')));
    } catch (error) {
      return null;
    }
  };
  const brief = (value) => String(JSON.stringify(value)).slice(0, 700);
  const b64 = (value) => Buffer.from(value).toString('base64');
  const php = (code) => t.php(`Module::getInstanceByName('prestaicore');\n${code}`);
  const root = (cmd) => execFileSync('docker', ['exec', t.env.ps, 'sh', '-c', cmd], { encoding: 'utf8' });
  const cli = (...args) => {
    try {
      return { code: 0, out: execFileSync('docker', ['exec', '-u', 'www-data', '-w', '/var/www/html', t.env.ps, 'php', 'bin/console', 'prestai:security:patches', ...args],
        { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }) };
    } catch (error) {
      return { code: error.status, out: String(error.stdout || '') };
    }
  };
  const shaIn = (file) => root(`[ -f /var/www/html/${file} ] && sha256sum /var/www/html/${file} | cut -d' ' -f1 || echo absent`).trim();
  const stamp = () => String(Date.now()) + crypto.randomBytes(2).toString('hex');
  const base = t.env.base;
  const admin = `${base}/${t.env.admin}`;

  const catalogBytes = fs.readFileSync(path.join(ROOT, 'catalog', 'catalog.json'));
  const catalog = JSON.parse(catalogBytes);
  const version = String(php('echo _PS_VERSION_;')).trim();
  const patches = Object.entries(catalog.patches).filter(([, p]) => p.versions[version]).map(([key, p]) => Object.assign({ key, files: p.versions[version] }, p));
  const keys = patches.map((p) => p.key);
  const has = (key) => keys.includes(key);
  t.check(`PrestaShop ${version} : ${patches.length} correctif(s) du catalogue ${catalog.number} pour cette version (${keys.join(', ') || 'aucun'})`, patches.length > 0, keys);

  // The patched files in the shop, as --files reads them.
  const dist = path.join(ROOT, 'dist', 'files');
  t.check('Fichiers corrigés construits (bin/build --dist)', fs.existsSync(dist) && patches.every((p) => p.files.every((f) => fs.existsSync(path.join(dist, f.after)))), dist);
  root('rm -rf /tmp/prestai-patches && mkdir -p /tmp/prestai-patches');
  execFileSync('docker', ['cp', dist + '/.', `${t.env.ps}:/tmp/prestai-patches/files`]);
  root('chown -R www-data:www-data /tmp/prestai-patches && chmod -R a+rX /tmp/prestai-patches');

  // The logs as they are before the test: what the attacks leave there is checked, then removed (run.sh reads them).
  const marks = php(`$files = [];
foreach (glob(_PS_ROOT_DIR_ . '/var/logs/*.log') ?: [] as $file) { clearstatcache(true, $file); $files[basename($file)] = filesize($file); }
echo json_encode(['log' => (int) Db::getInstance()->getValue('SELECT MAX(id_log) FROM ' . _DB_PREFIX_ . 'log'), 'files' => $files]);`);

  // 1. The catalog accepted by Core.
  let accepted;
  if (process.env.PATCHES_SIGNED === '1') {
    const signature = fs.readFileSync(path.join(ROOT, 'catalog', 'catalog.json.sig'));
    accepted = json(php(`echo json_encode(PrestaiCoreSecurityCatalog::accept(base64_decode('${b64(catalogBytes)}'), base64_decode('${b64(signature)}')));`)) || {};
    t.check('Catalogue signé : accepté par Core avec ses propres clés (principale ou secours)', accepted.ok === true && accepted.number === catalog.number, brief(accepted));
  } else {
    accepted = json(php(`$key = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
$json = base64_decode('${b64(catalogBytes)}');
openssl_sign($json, $signature, $key, OPENSSL_ALGO_SHA256);
echo json_encode(PrestaiCoreSecurityCatalog::accept($json, $signature, ['ci0000000000test' => openssl_pkey_get_details($key)['key']]));`)) || {};
    t.check('Catalogue non signé (avant la publication) : accepté par Core avec une clé de test donnée au code', accepted.ok === true && accepted.number === catalog.number, brief(accepted));
  }

  // 2. The state on the clean shop.
  const state = () => json(php(`PrestaiCoreSecurityCatalog::reset();
$s = PrestaiCoreSecurityState::compute();
echo json_encode(['advisories' => array_map(function ($a) { return $a['state'] . ':' . $a['reason']; }, $s['advisories']), 'patches' => array_map(function ($p) { return $p['status']; }, $s['patches'])]);`)) || {};
  let s = state();
  const expected = {};
  for (const advisory of catalog.advisories) {
    if (advisory.fixed_in && cmp(version, advisory.fixed_in) >= 0 && cmp(version, advisory.from) >= 0) {
      expected[advisory.id] = 'integrated';
    } else if (advisory.way === 'patch' && has(advisory.patch)) {
      expected[advisory.id] = 'to_apply';
    }
  }
  const wrong = Object.entries(expected).filter(([id, st]) => !String((s.advisories || {})[id]).startsWith(st + ':')).map(([id]) => `${id}=${(s.advisories || {})[id]}`);
  t.check('Boutique propre : chaque correctif de cette version « à appliquer » (fichiers officiels), chaque avis corrigé dans cette version « intégré »',
    keys.every((k) => (s.patches || {})[k] === 'to_apply') && wrong.length === 0, brief({ patches: s.patches, wrong }));
  for (const patch of patches) {
    const off = patch.files.filter((f) => shaIn(f.path) !== (f.before === 'absent' ? 'absent' : f.before)).map((f) => f.path);
    t.check(`${patch.key} : fichiers de la boutique propre identiques aux empreintes « avant » du catalogue (${patch.files.length})`, off.length === 0, off);
  }

  // The flaws, each one a function giving what an attacker gets.
  const customer = (prefix, run) => json(php(`$stamp = '${run}';
$hashing = new PrestaShop\\PrestaShop\\Core\\Crypto\\Hashing();
$c = new Customer(); $c->firstname = 'Secu'; $c->lastname = 'Proof'; $c->email = '${prefix}-' . $stamp . '@example.com';
$c->passwd = $hashing->hash('${PASSWD}'); $c->id_lang = (int) Configuration::get('PS_LANG_DEFAULT'); $c->active = 1; $c->add();
echo json_encode(['id' => (int) $c->id, 'email' => $c->email, 'secure_key' => $c->secure_key]);`)) || {};

  // B17: an order whose product carries a customization file, the file asked with no cookie.
  const b17 = async () => {
    const run = stamp();
    const order = json(php(`$stamp = '${run}';
Context::getContext()->container = PrestaShop\\PrestaShop\\Adapter\\ContainerBuilder::getContainer('front', _PS_MODE_DEV_);
Configuration::updateValue('PS_ORDER_OUT_OF_STOCK', 1);
$db = Db::getInstance();
$idLang = (int) Configuration::get('PS_LANG_DEFAULT');
$idProduct = (int) $db->getValue('SELECT id_product FROM ' . _DB_PREFIX_ . 'product WHERE active = 1 ORDER BY id_product');
$idCarrier = (int) $db->getValue('SELECT id_carrier FROM ' . _DB_PREFIX_ . 'carrier WHERE active = 1 AND deleted = 0 ORDER BY id_carrier');
$idField = (int) $db->getValue('SELECT id_customization_field FROM ' . _DB_PREFIX_ . 'customization_field WHERE id_product = ' . $idProduct . ' AND type = ' . Product::CUSTOMIZE_FILE . ' AND is_deleted = 0');
if (!$idField) {
    $db->insert('customization_field', ['id_product' => $idProduct, 'type' => Product::CUSTOMIZE_FILE, 'required' => 0, 'is_module' => 0, 'is_deleted' => 0]);
    $idField = (int) $db->Insert_ID();
    foreach (Language::getIDs(false) as $id) { $db->insert('customization_field_lang', ['id_customization_field' => $idField, 'id_lang' => $id, 'id_shop' => 1, 'name' => 'Logo']); }
    $db->update('product', ['customizable' => 1, 'uploadable_files' => 1], 'id_product = ' . $idProduct);
    $db->update('product_shop', ['customizable' => 1, 'uploadable_files' => 1], 'id_product = ' . $idProduct);
}
$hashing = new PrestaShop\\PrestaShop\\Core\\Crypto\\Hashing();
$c = new Customer(); $c->firstname = 'Secu'; $c->lastname = 'Upload'; $c->email = 'secu-b17-' . $stamp . '@example.com';
$c->passwd = $hashing->hash('${PASSWD}'); $c->id_lang = $idLang; $c->active = 1; $c->add();
$a = new Address(); $a->id_customer = $c->id; $a->alias = 'Home'; $a->firstname = 'Secu'; $a->lastname = 'Upload'; $a->address1 = '1 rue de la Paix';
$a->postcode = '75002'; $a->city = 'Paris'; $a->id_country = (int) Country::getByIso('FR'); $a->phone = '0102030405'; $a->add();
$g = new Guest(); $g->id_customer = $c->id; $g->add();
$cart = new Cart(); $cart->id_guest = (int) $g->id; $cart->id_customer = $c->id; $cart->id_address_delivery = $a->id; $cart->id_address_invoice = $a->id; $cart->id_lang = $idLang;
$cart->id_currency = (int) Configuration::get('PS_CURRENCY_DEFAULT'); $cart->id_carrier = $idCarrier; $cart->secure_key = $c->secure_key; $cart->id_shop = 1; $cart->add();
$context = Context::getContext(); $context->cart = $cart; $context->customer = $c; $context->currency = new Currency((int) $cart->id_currency); $context->language = new Language($idLang); $context->shop = new Shop(1);
$file = md5(uniqid((string) $stamp, true));
file_put_contents(_PS_UPLOAD_DIR_ . $file, 'PRESTAI-B17-SECRET-' . $stamp);
file_put_contents(_PS_UPLOAD_DIR_ . $file . '_small', 'PRESTAI-B17-SMALL-' . $stamp);
$db->insert('customization', ['id_product_attribute' => 0, 'id_address_delivery' => (int) $a->id, 'id_cart' => (int) $cart->id, 'id_product' => $idProduct, 'quantity' => 0, 'in_cart' => 0]);
$idCustomization = (int) $db->Insert_ID();
$db->insert('customized_data', ['id_customization' => $idCustomization, 'type' => Product::CUSTOMIZE_FILE, 'index' => $idField, 'value' => $file, 'id_module' => 0, 'price' => 0, 'weight' => 0]);
$cart->updateQty(1, $idProduct, 0, $idCustomization);
$db->update('customization', ['quantity' => 1, 'in_cart' => 1, 'id_address_delivery' => (int) $a->id], 'id_customization = ' . $idCustomization);
$cart->setDeliveryOption([(int) $a->id => $idCarrier . ',']); $cart->update();
$module = Module::getInstanceByName('ps_wirepayment');
$module->validateOrder((int) $cart->id, (int) Configuration::get('PS_OS_BANKWIRE'), (float) $cart->getOrderTotal(true, Cart::BOTH), 'Bank wire', null, [], null, false, $c->secure_key);
$order = new Order((int) $module->currentOrder);
echo json_encode(['order' => (int) $order->id, 'reference' => $order->reference, 'secure_key' => $order->secure_key, 'file' => $file]);`)) || {};
    const ask = async (query) => {
      const response = await fetch(`${base}/index.php?controller=upload&file=${order.file}${query}`, { redirect: 'follow' });
      return (await response.text()).includes(`PRESTAI-B17-SECRET-${run}`) ? 'fichier' : 'refus';
    };
    return { order: order.order, refOnly: await ask(`&reference=${order.reference}`), withKey: await ask(`&reference=${order.reference}&secure_key=${order.secure_key}`),
      wrongKey: await ask(`&reference=${order.reference}&secure_key=00000000000000000000000000000000`) };
  };

  // B18: a customer and an employee ask a new password; the token computed from the time and the secure key.
  const b18 = async () => {
    const run = stamp();
    const d = json(php(`$stamp = '${run}';
$hashing = new PrestaShop\\PrestaShop\\Core\\Crypto\\Hashing();
$idLang = (int) Configuration::get('PS_LANG_DEFAULT');
$c = new Customer(); $c->firstname = 'Secu'; $c->lastname = 'Reset'; $c->email = 'secu-b18-' . $stamp . '@example.com';
$c->passwd = $hashing->hash('${PASSWD}'); $c->id_lang = $idLang; $c->active = 1; $c->add();
$t1 = time(); $c->stampResetPasswordToken(); $c->update(); $t2 = time();
$token = (string) Db::getInstance()->getValue('SELECT reset_password_token FROM ' . _DB_PREFIX_ . 'customer WHERE id_customer = ' . (int) $c->id);
$predicted = '';
for ($t = $t1 - 2; $t <= $t2 + 2; ++$t) { if (hash_equals($token, sha1($t . $c->id . '-' . $c->secure_key))) { $predicted = $token; } }
$e = new Employee(); $e->firstname = 'Secu'; $e->lastname = 'Reset'; $e->email = 'secu-b18-' . $stamp . '@example.com';
$e->passwd = $hashing->hash('${PASSWD}'); $e->id_profile = 1; $e->id_lang = $idLang; $e->active = 1; $e->default_tab = 1; $e->add();
$e->stampResetPasswordToken(); $e->update();
echo json_encode(['id' => (int) $c->id, 'secure_key' => $c->secure_key, 'token' => $token, 'predictable' => $predicted !== '', 'computed' => sha1($t1 . $c->id . '-' . $c->secure_key),
  'employee' => (int) $e->id, 'employee_token' => (string) Db::getInstance()->getValue('SELECT reset_password_token FROM ' . _DB_PREFIX_ . 'employee WHERE id_employee = ' . (int) $e->id)]);`)) || {};
    const front = async (token) => {
      const html = await (await fetch(`${base}/index.php?controller=password&token=${d.secure_key}&id_customer=${d.id}&reset_token=${token}`)).text();
      return /name="passwd"/.test(html) ? 'formulaire' : 'refus';
    };
    const passwd = () => String(php(`echo Db::getInstance()->getValue('SELECT passwd FROM ' . _DB_PREFIX_ . 'employee WHERE id_employee = ${Number(d.employee) || 0}');`)).trim();
    const back = async (token) => {
      const page = await t.page();
      const url = `${admin}/index.php/reset-password/${token}`;
      await page.goto(url);
      const csrf = await page.evaluate(() => (document.querySelector('input[name="reset_password[_token]"]') || {}).value || '');
      const before = passwd();
      await page.context().request.post(url, { form: { 'reset_password[new_password][first]': 'Nouveau-Secu-2026!', 'reset_password[new_password][second]': 'Nouveau-Secu-2026!', 'reset_password[_token]': csrf } });
      await page.context().close();
      return passwd() !== before ? 'changé' : 'refus';
    };
    return { predictable: d.predictable, computed: await front(d.computed), stored: await front(d.token), employeeWrong: await back('0123456789abcdef0123456789abcdef01234567'), employeeStored: await back(d.employee_token) };
  };

  // The back office, logged in as the administrator (or another employee).
  const login = async (email = t.env.adminMail, passwd = t.env.adminPasswd) => {
    const page = await t.page();
    await page.goto(`${admin}/index.php?controller=AdminLogin`);
    await page.fill('#email', email);
    await page.fill('#passwd', passwd);
    await Promise.all([page.waitForLoadState('networkidle'), page.click('#submit_login')]);
    return page;
  };
  const linkTo = (page, part) => page.evaluate((p) => { const a = [...document.querySelectorAll('a[href]')].find((x) => x.href.includes(p)); return a ? a.href : null; }, part);

  // A1 to A5: the catch-up of 9.1.5 (versions before 9.1.5).
  const catchUp = async () => {
    const run = stamp();
    const data = json(php(`$stamp = '${run}';
$hashing = new PrestaShop\\PrestaShop\\Core\\Crypto\\Hashing();
$idLang = (int) Configuration::get('PS_LANG_DEFAULT');
$e = new Employee(); $e->firstname = 'Secu'; $e->lastname = 'Translator'; $e->email = 'secu-translator-' . $stamp . '@example.com';
$e->passwd = $hashing->hash('${PASSWD}'); $e->id_profile = 3; $e->id_lang = $idLang; $e->active = 1; $e->default_tab = (int) Tab::getIdFromClassName('AdminTranslations'); $e->add();
foreach (['CIA3ONE', 'CIA3TWO'] as $code) {
    if (!CartRule::getIdByCode($code)) {
        $r = new CartRule(); foreach (Language::getIDs(false) as $id) { $r->name[$id] = 'Secu ' . $code; }
        $r->code = $code; $r->reduction_percent = 5; $r->quantity = 10; $r->quantity_per_user = 1; $r->date_from = date('Y-m-d H:i:s', time() - 3600);
        $r->date_to = date('Y-m-d H:i:s', time() + 86400 * 30); $r->active = 1; $r->add();
    }
}
$c = new Customer(); $c->firstname = 'Secu'; $c->lastname = 'Formula'; $c->email = 'secu-formula-' . $stamp . '@example.com';
$c->passwd = $hashing->hash('${PASSWD}'); $c->id_lang = $idLang; $c->active = 1; $c->add();
Db::getInstance()->update('customer', ['lastname' => '=1+2'], 'id_customer = ' . (int) $c->id);
echo json_encode(['translator' => $e->email]);`)) || {};
    const out = {};
    // A1: an image of the CSV import asked from the internal network (a server of the test on 127.0.0.1:9999).
    root(`cat > /tmp/prestai-patches/a1-router.php <<'PHP'
<?php
file_put_contents('/tmp/prestai-patches/ssrf.log', date('c') . ' ' . $_SERVER['REQUEST_URI'] . "\\n", FILE_APPEND);
header('Content-Type: image/jpeg');
$im = imagecreatetruecolor(8, 8); imagejpeg($im); imagedestroy($im);
PHP
rm -f /tmp/prestai-patches/ssrf.log; chmod a+r /tmp/prestai-patches/a1-router.php; (php -S 127.0.0.1:9999 /tmp/prestai-patches/a1-router.php > /dev/null 2>&1 &); sleep 1`);
    const copied = json(php(`$image = new Image(); $image->id_product = 1; $image->position = Image::getHighestPosition(1) + 1; $image->add();
$method = new ReflectionMethod('AdminImportController', 'copyImg'); $method->setAccessible(true);
$ok = $method->invoke(null, 1, (int) $image->id, 'http://127.0.0.1:9999/internal-admin/secret.jpg', 'products', false);
$image->delete();
echo json_encode(['copied' => (bool) $ok]);`)) || {};
    const reached = Number(root('wc -l < /tmp/prestai-patches/ssrf.log 2>/dev/null || echo 0').trim()) || 0;
    // The bracket keeps pkill from matching its own shell, whose command line holds the pattern.
    root('pkill -f "php -S 127.0.0.1:999[9]" || true');
    out.A1 = copied.copied || reached > 0 ? 'réseau interne atteint' : 'refus';
    // A2: maintenance open to 1.2.3.4 only; the address written by the visitor in X-Forwarded-For.
    const was = json(php(`echo json_encode(['enable' => Configuration::get('PS_SHOP_ENABLE'), 'ips' => Configuration::get('PS_MAINTENANCE_IP')]);`)) || {};
    php(`Configuration::updateValue('PS_SHOP_ENABLE', 0); Configuration::updateValue('PS_MAINTENANCE_IP', '1.2.3.4'); echo 'ok';`);
    const spoofed = (await fetch(`${base}/`, { headers: { 'X-Forwarded-For': '1.2.3.4, 5.6.7.8' }, redirect: 'manual' })).status;
    php(`Configuration::updateValue('PS_SHOP_ENABLE', ${Number(was.enable) ? 1 : 0}); Configuration::updateValue('PS_MAINTENANCE_IP', base64_decode('${b64(String(was.ips || ''))}')); echo 'ok';`);
    out.A2 = spoofed === 200 ? 'maintenance contournée' : `refus (${spoofed})`;
    // A5: the export of the customers, the last name « =1+2 ».
    const page = await login();
    await page.goto(await linkTo(page, 'sell/customers/?'));
    const exportUrl = await linkTo(page, 'customers/export');
    const csv = exportUrl ? await (await page.context().request.get(exportUrl)).text() : '';
    out.A5 = /;'=1\+2;/.test(csv) ? 'refus' : (/;=1\+2;/.test(csv) ? 'formule brute' : 'introuvable');
    out.exportHeader = csv.split('\n')[0].slice(0, 40);
    // A3: the legacy list of the cart rules filtered with an alias carrying a subquery, true then false.
    const rows = async (alias) => {
      const session = await login();
      const url = await linkTo(session, 'controller=AdminCartRules');
      const form = { submitFiltercart_rule: '1' };
      form[`cart_ruleFilter_${alias}!code`] = 'zzzz';
      const html = await (await session.context().request.post(url, { form })).text();
      const table = (html.match(/<table[^>]*id="table-cart_rule"[\s\S]*?<\/table>/) || [''])[0];
      await session.context().close();
      return { rows: new Set(table.match(/id_cart_rule=\d+/g) || []).size, sqlError: /Unknown column|SQL syntax|PrestaShopDatabaseException/.test(html) };
    };
    const q = (c) => `(SELECT/**/COUNT(*)/**/FROM/**/${'ps_'}employee/**/WHERE/**/id_employee=1/**/AND/**/ASCII(SUBSTRING(passwd,1,1))=${c})=1/**/OR/**/a`;
    const yes = await rows(q(36));
    const no = await rows(q(37));
    // Fixed, the alias is a column name: an SQL error (Unknown column), as on 9.1.5 itself, and no more oracle.
    out.A3 = yes.rows !== no.rows ? 'sous-requête exécutée' : 'refus';
    out.A3sql = yes.sqlError || no.sqlError;
    // Normal use of the same list: filtered on a code.
    const url = await linkTo(page, 'controller=AdminCartRules');
    const html = await (await page.context().request.post(url, { form: { submitFiltercart_rule: '1', cart_ruleFilter_code: 'CIA3ONE' } })).text();
    out.filter = new Set(((html.match(/<table[^>]*id="table-cart_rule"[\s\S]*?<\/table>/) || [''])[0]).match(/id_cart_rule=\d+/g) || []).size;
    await page.context().request.post(url, { form: { submitResetcart_rule: '1' } });
    // A4: the notifications asked by an employee with the profile Translator; the administrator's.
    // The translator lands on Translations, a page of its profile (the dashboard would refuse it).
    const translator = await login(data.translator, PASSWD);
    const token = new URL(translator.url()).searchParams.get('_token')
      || await translator.evaluate(() => { const a = [...document.querySelectorAll('a[href*="_token="]')][0]; return a ? new URL(a.href).searchParams.get('_token') : null; });
    const body = await (await translator.context().request.post(`${admin}/index.php/common/notifications?_token=${token}`)).text();
    out.A4 = /Formula/.test(body) ? 'données clients visibles' : 'refus';
    const adminToken = new URL(page.url()).searchParams.get('_token') || token;
    const notifications = await page.context().request.post(`${admin}/index.php/common/notifications?_token=${adminToken}`);
    out.notifications = notifications.status();
    await translator.context().close();
    await page.context().close();
    return out;
  };

  // B8 / B9: free carts (a voucher of 100 %, free shipping); each free order asked several times at once.
  const freeCarts = (scenario, count, uses) => json(php(`$stamp = '${stamp()}';
Context::getContext()->container = PrestaShop\\PrestaShop\\Adapter\\ContainerBuilder::getContainer('front', _PS_MODE_DEV_);
Configuration::updateValue('PS_CART_FOLLOWING', 1);
Configuration::updateValue('PS_ORDER_OUT_OF_STOCK', 1);
$idLang = (int) Configuration::get('PS_LANG_DEFAULT');
$idProduct = (int) Db::getInstance()->getValue('SELECT id_product FROM ' . _DB_PREFIX_ . 'product WHERE active = 1 ORDER BY id_product');
$idCarrier = (int) Db::getInstance()->getValue('SELECT id_carrier FROM ' . _DB_PREFIX_ . 'carrier WHERE active = 1 AND deleted = 0 ORDER BY id_carrier');
$rule = null;
if (${uses} > 0) {
    $rule = new CartRule();
    foreach (Language::getIDs(false) as $id) { $rule->name[$id] = 'CI ${scenario}'; }
    $rule->code = 'CI' . strtoupper('${scenario}') . $stamp; $rule->reduction_percent = 100; $rule->free_shipping = 1; $rule->quantity = ${uses}; $rule->quantity_per_user = 100;
    $rule->date_from = date('Y-m-d H:i:s', time() - 3600); $rule->date_to = date('Y-m-d H:i:s', time() + 86400); $rule->active = 1; $rule->add();
}
$out = ['rule' => $rule ? (int) $rule->id : 0, 'carts' => []];
$hashing = new PrestaShop\\PrestaShop\\Core\\Crypto\\Hashing();
for ($i = 0; $i < ${count}; ++$i) {
    $c = new Customer(); $c->firstname = 'Secu'; $c->lastname = 'Proof'; $c->email = 'secu-${scenario}-' . $i . '-' . $stamp . '@example.com';
    $c->passwd = $hashing->hash('${PASSWD}'); $c->id_lang = $idLang; $c->active = 1; $c->add();
    $a = new Address(); $a->id_customer = $c->id; $a->alias = 'Home'; $a->firstname = 'Secu'; $a->lastname = 'Proof'; $a->address1 = '1 rue de la Paix';
    $a->postcode = '75002'; $a->city = 'Paris'; $a->id_country = (int) Country::getByIso('FR'); $a->phone = '0102030405'; $a->add();
    $g = new Guest(); $g->id_customer = $c->id; $g->add();
    $cart = new Cart(); $cart->id_guest = (int) $g->id; $cart->id_customer = $c->id; $cart->id_address_delivery = $a->id; $cart->id_address_invoice = $a->id; $cart->id_lang = $idLang;
    $cart->id_currency = (int) Configuration::get('PS_CURRENCY_DEFAULT'); $cart->id_carrier = $idCarrier; $cart->secure_key = $c->secure_key; $cart->id_shop = 1; $cart->add();
    $context = Context::getContext(); $context->cart = $cart; $context->customer = $c; $context->currency = new Currency((int) $cart->id_currency); $context->language = new Language($idLang); $context->shop = new Shop(1);
    $cart->updateQty(1, $idProduct);
    $cart->setDeliveryOption([(int) $a->id => $idCarrier . ',']); $cart->update();
    if ($rule) { $cart->addCartRule((int) $rule->id); }
    $out['carts'][] = ['email' => $c->email, 'cart' => (int) $cart->id, 'total' => (float) $cart->getOrderTotal(true, Cart::BOTH)];
}
echo json_encode($out);`)) || { carts: [] };
  const customerSession = async (email) => {
    const page = await t.page();
    await page.goto(`${base}/index.php?controller=authentication`);
    await page.fill('#login-form [name="email"]', email);
    await page.fill('#login-form [name="password"]', PASSWD);
    await Promise.all([page.waitForLoadState('load'), page.click('#login-form button[type="submit"], #submit-login')]);
    return page;
  };
  const counts = (rule, carts) => json(php(`$orders = [];
foreach ([${carts.join(',')}] as $id) { $orders[$id] = (int) Db::getInstance()->getValue('SELECT COUNT(*) FROM ' . _DB_PREFIX_ . 'orders WHERE id_cart = ' . (int) $id); }
echo json_encode(['orders' => $orders, 'uses' => (int) Db::getInstance()->getValue('SELECT COUNT(*) FROM ' . _DB_PREFIX_ . 'order_cart_rule WHERE id_cart_rule = ${Number(rule) || 0}')]);`)) || {};
  const race = async (setup, times) => {
    const shots = [];
    const pages = [];
    for (const cart of setup.carts) {
      const page = await customerSession(cart.email);
      pages.push(page);
      // Only the cookie of PrestaShop, not PHPSESSID: the lock of the PHP session would make the requests wait.
      const cookie = (await page.context().cookies()).filter((c) => /^PrestaShop-/.test(c.name)).map((c) => `${c.name}=${c.value}`).join('; ');
      for (let i = 0; i < times; i += 1) {
        shots.push(fetch(`${base}/index.php?controller=order-confirmation&free_order=1&id_cart=${cart.cart}`, { redirect: 'manual', headers: { Cookie: cookie } }).catch(() => null));
      }
    }
    await Promise.all(shots);
    for (const page of pages) {
      await page.context().close();
    }
    return counts(setup.rule, setup.carts.map((c) => c.cart));
  };

  // 3. Before the patches: the flaws seen.
  const before = {};
  if (has('customization-file')) {
    before.B17 = await b17();
    t.check('Avant le correctif : B17 reproduite (fichier de personnalisation servi avec la référence seule)', before.B17.refOnly === 'fichier' && before.B17.withKey === 'fichier', brief(before.B17));
  }
  if (has('password-reset-token')) {
    before.B18 = await b18();
    t.check('Avant le correctif : B18 reproduite (jeton = sha1(heure . id - clé secrète), accepté par la page)', before.B18.predictable === true && before.B18.computed === 'formulaire', brief(before.B18));
  }
  if (has('catch-up-9-1-5')) {
    before.A = await catchUp();
    t.check('Avant le rattrapage : A1, A2, A3, A4, A5 reproduites', before.A.A1 !== 'refus' && before.A.A2 === 'maintenance contournée' && before.A.A3 === 'sous-requête exécutée'
      && before.A.A4 === 'données clients visibles' && before.A.A5 === 'formule brute', brief(before.A));
  }

  // 4. The patches applied by the console, each file checked.
  for (const patch of patches) {
    const result = cli('apply', patch.key, '--confirm=OUI', '--files=/tmp/prestai-patches/files');
    const off = patch.files.filter((f) => shaIn(f.path) !== f.after).map((f) => f.path);
    t.check(`${patch.key} appliqué par la console : ${patch.files.length} fichier(s) aux empreintes du catalogue`, result.code === 0 && new RegExp(`${patch.key}: applied`).test(result.out) && off.length === 0,
      brief({ code: result.code, out: result.out.slice(-300), off }));
  }
  s = state();
  t.check('Après application : chaque correctif « appliqué »', keys.every((k) => (s.patches || {})[k] === 'applied'), brief(s.patches));

  // 5. After: the flaws refused, normal use.
  if (has('concurrent-orders')) {
    const services = json(php(`$out = [];
$container = PrestaShop\\PrestaShop\\Adapter\\ContainerBuilder::getContainer('front', false);
foreach (['PrestaShop\\PrestaShop\\Adapter\\Order\\OrderCreationLock', 'PrestaShop\\PrestaShop\\Adapter\\CartRule\\CartRuleQuantityReserver'] as $id) {
    try { $out[substr($id, strrpos($id, '\\\\') + 1)] = get_class($container->get($id)); } catch (Throwable $e) { $out[substr($id, strrpos($id, '\\\\') + 1)] = 'absent'; }
}
echo json_encode($out);`)) || {};
    t.check('B8/B9 : services du verrou de commande et de la réservation du bon dans le conteneur du front (prod)', services.OrderCreationLock && services.OrderCreationLock !== 'absent'
      && services.CartRuleQuantityReserver && services.CartRuleQuantityReserver !== 'absent', brief(services));
    const b9 = freeCarts('b9', 1, 100);
    const b9Count = await race(b9, 6);
    t.check('B9 refusée : un panier gratuit demandé six fois en même temps donne une seule commande', Object.values(b9Count.orders || {}).join() === '1', brief(b9Count));
    const b8 = freeCarts('b8', 2, 1);
    const b8Count = await race(b8, 6);
    const orders = Object.values(b8Count.orders || {});
    t.check('B8 refusée : deux paniers, un bon d’une seule utilisation, six demandes chacun en même temps : le bon utilisé une fois', b8Count.uses === 1 && orders.every((n) => n <= 1),
      brief(b8Count));
    // Normal use: an order paid by bank wire, through the front office.
    const paid = freeCarts('paid', 1, 0);
    const page = await customerSession(paid.carts[0].email);
    const response = await page.context().request.post(`${base}/index.php?fc=module&module=ps_wirepayment&controller=validation`, { maxRedirects: 0, form: {} });
    await page.context().close();
    const paidCount = counts(0, paid.carts.map((c) => c.cart));
    t.check('Usage normal : commande payée par virement depuis le front (une commande)', Object.values(paidCount.orders || {}).join() === '1', brief({ status: response.status(), paidCount }));
    const one = freeCarts('one', 1, 5);
    const oneCount = await race(one, 1);
    t.check('Usage normal : commande gratuite avec un bon de réduction (une commande, le bon utilisé une fois)', Object.values(oneCount.orders || {}).join() === '1' && oneCount.uses === 1, brief(oneCount));
  }
  if (has('customization-file')) {
    const after = await b17();
    t.check('B17 refusée : référence seule ou mauvaise clé refusées, référence et clé de la commande servent le fichier',
      after.refOnly === 'refus' && after.wrongKey === 'refus' && after.withKey === 'fichier', brief(after));
  }
  if (has('password-reset-token')) {
    const after = await b18();
    t.check('B18 refusée : jeton aléatoire (pas sha1(heure . id - clé)), jeton calculé refusé, jeton reçu accepté ; employé : faux jeton refusé, vrai jeton accepté',
      after.predictable === false && after.computed === 'refus' && after.stored === 'formulaire' && after.employeeWrong === 'refus' && after.employeeStored === 'changé', brief(after));
  }
  if (has('catch-up-9-1-5')) {
    const after = await catchUp();
    t.check('A1 à A5 refusées après le rattrapage ; usage normal : liste filtrée (1 ligne), notifications (200), export des clients',
      after.A1 === 'refus' && after.A2 !== 'maintenance contournée' && after.A3 === 'refus' && after.A4 === 'refus' && after.A5 === 'refus'
      && after.filter === 1 && after.notifications === 200 && /;/.test(after.exportHeader), brief(after));
  }

  // 6. Reverted by the console: the official files back.
  for (const patch of patches.slice().reverse()) {
    const result = cli('revert', patch.key, '--confirm=OUI');
    const off = patch.files.filter((f) => shaIn(f.path) !== (f.before === 'absent' ? 'absent' : f.before)).map((f) => f.path);
    t.check(`${patch.key} retiré par la console : fichiers officiels remis, fichiers nouveaux supprimés`, result.code === 0 && off.length === 0, brief({ code: result.code, out: result.out.slice(-200), off }));
  }
  s = state();
  t.check('Après le retour arrière : chaque correctif de nouveau « à appliquer »', keys.every((k) => (s.patches || {})[k] === 'to_apply'), brief(s.patches));
  if (has('customization-file')) {
    const again = await b17();
    t.check('Après le retour arrière : B17 de nouveau reproduite (le retour arrière remet bien le code d’origine)', again.refOnly === 'fichier', brief(again));
  }

  // 7. The traces of the attacks refused, expected in the logs: counted, then removed, and only them (the lines and
  // rows written since the start of the test that carry these messages).
  const noise = {
    cart: 'Cart cannot be loaded or an order has already been placed using this cart',
    column: "Unknown column '(SELECT/**/COUNT(*)/**/FROM/**/",
    denied: 'You do not have permission to view this.',
  };
  const removed = json(php(`$marks = json_decode(base64_decode('${b64(marks)}'), true);
$noise = json_decode(base64_decode('${b64(JSON.stringify(noise))}'), true);
$removed = array_fill_keys(array_keys($noise), 0);
foreach (glob(_PS_ROOT_DIR_ . '/var/logs/*.log') ?: [] as $file) {
    $from = isset($marks['files'][basename($file)]) ? (int) $marks['files'][basename($file)] : 0;
    $all = (string) file_get_contents($file);
    $kept = [];
    foreach (explode("\n", substr($all, $from)) as $line) {
        $hit = null;
        foreach ($noise as $key => $text) { if (strpos($line, $text) !== false) { $hit = $key; } }
        if ($hit === null) { $kept[] = $line; } else { ++$removed[$hit]; }
    }
    file_put_contents($file, substr($all, 0, $from) . implode("\n", $kept));
}
$db = Db::getInstance();
foreach ($noise as $key => $text) {
    $where = 'id_log > ' . (int) $marks['log'] . " AND message LIKE '" . pSQL($text) . "%'";
    $removed[$key] += (int) $db->getValue('SELECT COUNT(*) FROM ' . _DB_PREFIX_ . 'log WHERE ' . $where);
    $db->delete('log', $where);
}
echo json_encode($removed);`)) || {};
  t.check('Journaux : traces attendues des attaques refusées, comptées puis retirées (paniers en double refusés par le verrou'
    + (has('catch-up-9-1-5') ? ', colonne inconnue de A3, 403 de A4' : '') + ')',
    (!has('concurrent-orders') || removed.cart > 0) && (!has('catch-up-9-1-5') || (removed.column > 0 && removed.denied > 0)), brief(removed));
});

// -1, 0, 1 as version_compare.
function cmp(a, b) {
  const x = String(a).split('.').map(Number);
  const y = String(b).split('.').map(Number);
  for (let i = 0; i < Math.max(x.length, y.length); i += 1) {
    const d = (x[i] || 0) - (y[i] || 0);
    if (d) {
      return d < 0 ? -1 : 1;
    }
  }
  return 0;
}

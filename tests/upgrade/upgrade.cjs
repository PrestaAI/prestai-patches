// upgrade.cjs: the patches of the catalog across an upgrade of PrestaShop by its update assistant (bin/upgrade of
// prestai-ci 1.19.0), as on a shop that stays on 9.1.x then moves on.
// - UPGRADE_STEP unset (run.sh, on the oldest version of the catalog, the shop kept: KEEP=1): the catalog accepted by
//   Core (signed: PATCHES_SIGNED=1, else a key made here), every patch of the version applied by the console;
// - UPGRADE_STEP=after (after bin/upgrade <version>): the state read by the console (status reconciles), then for
//   each patch applied before the upgrade: « integrated » when the new version fixes all its advisories (its backup
//   removed, its files left as the assistant wrote them), else « overwritten » and to apply again, then applied again
//   with the files of the new version. The assistant put back the official files: none is modified.
'use strict';
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const ci = require(process.env.PRESTAI_CI_TEST);

const ROOT = process.env.PATCHES_DIR || path.resolve(__dirname, '..', '..');

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
  const cli = (...args) => {
    try {
      return { code: 0, out: execFileSync('docker', ['exec', '-u', 'www-data', '-w', '/var/www/html', t.env.ps, 'php', 'bin/console', 'prestai:security:patches', ...args],
        { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }) };
    } catch (error) {
      return { code: error.status, out: String(error.stdout || '') };
    }
  };
  const catalogBytes = fs.readFileSync(path.join(ROOT, 'catalog', 'catalog.json'));
  const catalog = JSON.parse(catalogBytes);
  const version = String(php('echo _PS_VERSION_;')).trim();
  const state = () => json(php(`PrestaiCoreSecurityCatalog::reset();
$s = PrestaiCoreSecurityState::compute();
echo json_encode(['patches' => array_map(function ($p) { return ['status' => $p['status'], 'journal' => $p['journal'] ? $p['journal']['state'] : null,
  'files' => array_map(function ($f) { return $f['path'] . '=' . $f['status']; }, $p['files'])]; }, $s['patches']),
  'backups' => array_map(function ($k) { return PrestaiCoreSecurityPatcher::hasBackup($k); }, array_combine(array_keys($s['patches']), array_keys($s['patches']))),
  'advisories' => array_map(function ($a) { return $a['state']; }, $s['advisories'])]);`)) || {};
  const files = () => {
    root('rm -rf /tmp/prestai-patches && mkdir -p /tmp/prestai-patches');
    execFileSync('docker', ['cp', path.join(ROOT, 'dist', 'files') + '/.', `${t.env.ps}:/tmp/prestai-patches/files`]);
    root('chown -R www-data:www-data /tmp/prestai-patches');
  };
  const root = (cmd) => execFileSync('docker', ['exec', t.env.ps, 'sh', '-c', cmd], { encoding: 'utf8' });
  const apply = (keys) => keys.map((key) => {
    const result = cli('apply', key, '--confirm=OUI', '--files=/tmp/prestai-patches/files');
    return { key, ok: result.code === 0 && new RegExp(`${key}: (applied|already_applied)`).test(result.out), out: result.out.slice(-160) };
  });

  if (process.env.UPGRADE_STEP !== 'after') {
    files();
    let accepted;
    if (process.env.PATCHES_SIGNED === '1') {
      const signature = fs.readFileSync(path.join(ROOT, 'catalog', 'catalog.json.sig'));
      accepted = json(php(`echo json_encode(PrestaiCoreSecurityCatalog::accept(base64_decode('${b64(catalogBytes)}'), base64_decode('${b64(signature)}')));`)) || {};
    } else {
      accepted = json(php(`$key = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
$json = base64_decode('${b64(catalogBytes)}');
openssl_sign($json, $signature, $key, OPENSSL_ALGO_SHA256);
echo json_encode(PrestaiCoreSecurityCatalog::accept($json, $signature, ['ci0000000000test' => openssl_pkey_get_details($key)['key']]));`)) || {};
    }
    t.check(`Catalogue ${catalog.number} accepté par Core (${process.env.PATCHES_SIGNED === '1' ? 'signature de la release, clés de Core' : 'clé de test donnée au code'})`, accepted.ok === true, brief(accepted));
    const keys = Object.keys(catalog.patches).filter((key) => catalog.patches[key].versions[version]);
    const results = apply(keys);
    const s = state();
    t.check(`PrestaShop ${version} : tous les correctifs de la version appliqués avant la montée (${keys.join(', ')})`,
      results.every((r) => r.ok) && keys.every((key) => s.patches[key].status === 'applied'), brief({ results, patches: s.patches }));
    return;
  }

  // After an upgrade.
  const before = state();
  const status = cli('status', '--json');
  const s = state();
  const fixed = (key) => catalog.patches[key].advisories.every((id) => {
    const advisory = catalog.advisories.find((a) => a.id === id);
    return advisory && advisory.fixed_in && cmp(version, advisory.fixed_in) >= 0;
  });
  const applied = Object.keys(before.patches || {}).filter((key) => before.patches[key].journal === 'applied');
  t.check(`PrestaShop ${version} par l'assistant : console « status » (qui réconcilie), ${applied.length} correctif(s) appliqué(s) avant la montée`, status.code === 0 && applied.length > 0,
    brief({ status: status.code, applied }));
  const integrated = applied.filter(fixed);
  const overwritten = applied.filter((key) => !fixed(key));
  t.check(`Intégrés par la montée (avis tous corrigés en ${version}) : ${integrated.join(', ') || 'aucun'} ; sauvegardes supprimées`,
    integrated.every((key) => s.patches[key].journal === 'integrated' && s.backups[key] === false), brief(integrated.map((key) => [key, s.patches[key], s.backups[key]])));
  const modified = Object.entries(s.patches || {}).filter(([, p]) => p.status === 'modified').map(([key]) => key);
  t.check(`Écrasés par la montée (fichiers officiels de ${version} remis) : ${overwritten.join(', ') || 'aucun'} ; aucun fichier « modifié »`,
    overwritten.every((key) => s.patches[key].journal === 'overwritten' && (s.patches[key].status === 'to_apply' || s.patches[key].status === 'none')) && modified.length === 0,
    brief({ overwritten: overwritten.map((key) => [key, s.patches[key]]), modified }));
  const again = overwritten.filter((key) => catalog.patches[key].versions[version]);
  files();
  const results = apply(again);
  const after = state();
  t.check(`De nouveau appliqués avec les fichiers de ${version} : ${again.join(', ') || 'aucun'}`, results.every((r) => r.ok) && again.every((key) => after.patches[key].status === 'applied'),
    brief({ results, patches: again.map((key) => [key, after.patches[key]]) }));
  const open = Object.entries(after.advisories || {}).filter(([id, st]) => {
    const advisory = catalog.advisories.find((a) => a.id === id);
    return advisory && advisory.way === 'patch' && st === 'to_apply';
  }).map(([id]) => id);
  t.check(`Aucun avis à correctif encore « à appliquer » en ${version}`, open.length === 0, open);
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

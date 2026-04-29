// js-safe-realrepo-006 — distilled from gogs `public/plugins/codemirror-5.17.0/
// mode/gherkin/gherkin.js` line 107.  The CodeMirror Gherkin tokenizer ships
// localised feature-keyword aliases as one large regex inside a boolean
// sub-condition.  The CFG builder textualises every sub-condition of a
// boolean chain and truncates that text to MAX_CONDITION_TEXT_LEN (256
// bytes) for diagnostics; naive byte-slice truncation panicked when byte
// 256 landed inside a multi-byte UTF-8 character (here Gurmukhi `ਖ`,
// 3-byte UTF-8).  Engine fix:
// `src/utils/snippet.rs::truncate_at_char_boundary`, applied at three CFG
// sites and two symex display sites.  Invariant: scanning this file must
// terminate without panicking the rayon worker, regardless of where byte
// 256 lands inside the regex.

function tokenLocalisedFeatureKeyword(stream, state) {
    if (
        !state.inKeywordLine &&
        state.allowFeature &&
        stream.match(/(機能|功能|フィーチャ|기능|โครงหลัก|ความสามารถ|ความต้องการทางธุรกิจ|ಹೆಚ್ಚಳ|గుణము|ಮುಹಾಂದರಾ|ਮੁਹਾਂਦਰਾ|ਨਕਸ਼ ਨੁਹਾਰ|ਖਾਸੀਅਤ|रूप लेख|وِیژگی|خاصية|תכונה|Функціонал|Функция|Функционалност|Функционал|Үзенчәлеклелек|Свойство|Особина|Мөмкинлек|Могућност|Λειτουργία|Δυνατότητα|Właściwość|Vlastnosť|Trajto|Tính năng|Savybė|Požiadavka|Požadavek|Potrzeba biznesowa|Özellik|Osobina|Ominaisuus|Omadus|Mogućnost|Mogucnost|Jellemző|Funzionalità|Funktionalitéit|Funktionalität|Funkcja|Funkcionalnost|Funkcionalitāte|Funkcia|Fungsi|Functionaliteit|Funcționalitate|Funcţionalitate|Functionalitate|Funcionalitat|Funcionalidade|Fonctionnalité|Fitur|Fīča|Feature|Eiginleiki|Egenskap|Egenskab|Característica|Caracteristica|Business Need|Aspekt|Arwedd|Ability):/)
    ) {
        state.inKeywordLine = true;
        return "keyword";
    }
    return null;
}

module.exports = { tokenLocalisedFeatureKeyword };

// FP guard / panic guard — CFG condition-text truncation must be UTF-8 safe.
//
// Reproduces the gogs scan crash where a CodeMirror Gherkin tokenizer ships a
// long localised regex inside a boolean sub-condition (`stream.match(/.../) &&
// other`).  When `push_condition_node` textualises the sub-expression, the
// regex literal exceeds MAX_CONDITION_TEXT_LEN (256 bytes); naive byte-slice
// truncation panicked when byte 256 landed inside a multi-byte UTF-8
// character (here Gurmukhi `ਖ`, three bytes).  Engine fix in
// `src/utils/snippet.rs::truncate_at_char_boundary`, applied at three CFG
// sites + two symex display sites.
//
// Invariant: scanning this file must terminate without panicking the rayon
// worker, regardless of where byte 256 lands.

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

// Sanity: also exercise the let-match-guard truncation site
// (`emit_rust_match_guard_if`) by way of a JS analogue with a CFG-relevant
// boolean chain that wraps localised text into the second branch.  The CFG
// builder still has to textualise both arms.
function classify(s) {
    if (
        s.length > 0 &&
        s.indexOf("ਨਕਸ਼ ਨੁਹਾਰ ਖਾਸੀਅਤ रूप लेख وِیژگی خاصية תכונה Функціонал Функция Функционалност Функционал Үзенчәлеклелек Свойство Особина Мөмкинлек Могућност Λειτουργία Δυνατότητα") >= 0
    ) {
        return "localised";
    }
    return "ascii";
}

module.exports = { tokenLocalisedFeatureKeyword, classify };

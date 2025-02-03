export function selectFirstMatch(peerArray, preferences){
   for (const preference of preferences) {
      if (peerArray.includes(preference)) {
        return preference; // Return the first match
      }
    }
    return null; // Return null if no match is found
}

export function selectKeyExchange(keyShareEntries, preferences){
   const groups = new Set(keyShareEntries.keys())
   return groups.intersection(preferences).values().next().value;//selectFirstMatch(groups, preferences);
}
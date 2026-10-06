# Game downloads facade

This document describes elements needed for completeness of the download logic.
The requirements indicate feature set that has to be abstracted across various file formats.  
Important to note: The transport is insecure `http://` - unless we understand the package signing we won't be able to validate if the data wasn't tampered with

## Requirements

- Quickly lookup packages
  - Calculate the download size per feature
  - Present toggles for download features with localization
  - Expose ability to control the language of the download (instead of enforcing system locale)
  - Find relevant Durables that have separate downloads
- Preloading
  - This may cover upcoming and released games - like for example you plan on buying a game or gamepass sub
  - MSIXVC2 can preload updates
- Estimate update sizes
  - it is a nice to have when GUI doesnt auto update, lets user know roughly how long it may take
- Runtime control
  - Support for change of priority of chunks when downloading
  - Support for uninstallation of chunks during the download
  - Download speed cap
- Chunk management
  - Enumerate available chunks, featurues, languages, tags
  - Progress reporting per query (Chunk Id, Feature, Language, Tag)
- Verify and repair


## Format specific notes

Fast package identification should be possible for all below formats. The topic of authencity verification is still a question mark.

### MSIXVC

Format is 4KiB aligned. When downloading, we expect the process will occur in multiples of page numbers.

Download tasks shouldn't be content-aware. They are to stream the file data as quickly as possible.

### MSIXVC2

Format appears to be a ZIP containing different boxes of data. 

### EAPPX MSIX

Out of scope currently - won't support most of features of MSIXVC and MSIXVC2